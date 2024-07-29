Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBDGFTW2QMGQE2RUJFBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id A5ACE93F141
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 11:36:14 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2ef1dbbf2c4sf1311311fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 02:36:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722245774; cv=pass;
        d=google.com; s=arc-20160816;
        b=wvIYuglCHdafjH07Jxoiq98iFrZHzegi1aB22CYfcGW7ArpBzxvZV33lI1zsb9Ggio
         6XyNkdIDq1iJfLVUI3tHcUyKt4ui1iZ09NT596RKVoHAYVTDsSivK8//RQ3/YbMwOoPL
         XjBS0ANFbiP2YRpAyH4oCMuQD+A7+3X6sfzev4zh8gLruuI2D6+RvJJro21uaQ4WCeYr
         Z10a720Ue72jFMzE4ja9IctXMxVxQmuVp9pxy10wlbgBeyAD2RgD56iXFYUWGbH+ISPV
         GjF2UMv4iF28cKiAR6hDpc8B702zFS8PhYLhcuU73fv/VfYuVO7wJ8X5xGxEEpbIwn8Q
         j4lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tOd9AN7luuGwYTp0p1c2hvagT1oSCfnEGvut3bWA08Q=;
        fh=QJTCDFaX27mRyH66IBUFuVlXt43W1cZOBGqe9u1G1Hk=;
        b=lV6v6GtJlPCxTE9t4eXZmR/dY0G+nH3q7EkZOFO4ul0UbYZWexs4Oc5pgWDnU6Bb7y
         NpQtL3Bwa2384llpLLkFtnE8B3vfcWZqS+xSSEHPInEFuc9G290QOCbldvASNURlPxvr
         hXfq3/wCSD+IUh1Oo+B8mlAlETpr1bo7yXQivZAFgwZC7j0mLVOKqbfHs7OmHP7hfPI3
         3rqD+vLoXRjvMAFS6sxcMBrWRFWGwtg7v0jsLgbYJSc1g5t0GD7M8abbNW3PeBp6KZeM
         eDzyS83GfkfQhOdRQoENAQJtyKc8HvdLvgvJzZUqn02YJxawTbFAMzeLbAPsCW9jN1SX
         K91w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NlJcQuGQ;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722245774; x=1722850574; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tOd9AN7luuGwYTp0p1c2hvagT1oSCfnEGvut3bWA08Q=;
        b=o+kAFc3nX78pE1hjy/MztVFqqvN3dVn0C6kXyf1ifeHHIgB3okQpYMcwTcHSxkEXgQ
         s6+eRbUQcyf6QStyV7r3TAmHDfcvB+bPaiGqOHock3JqT3cXrwNm2hk5thGO7vWVWfO+
         mmNEUkUMrt9FI6zRR2pQm4z14P4Yv/x28w+tOyRX2X9opdeja8h3QtKXBfOiLUQzjNny
         ZTOHBsFaMo4LeL+H9mCzOqW62rrHqxoQ/PL9oiDisVDi8Ag18jTQ/wloHltzEMcXpGHu
         42LKTiguQIb1k+aWXr26nDeangoOXF9uXCzHVI/6EG/VDbjP7ud+OW4uHOPqZpmEFPoZ
         hQZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722245774; x=1722850574;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tOd9AN7luuGwYTp0p1c2hvagT1oSCfnEGvut3bWA08Q=;
        b=WBpPN9FThqmO07tby6cnPFQNprO2zglNtXNi1sXowwZQZM37xIZExlHRdZHZeawGD2
         puWTDeR0GRxmx6ledJSbxWMd4qAsPofZFHETzhox8RCgfunaPMRnGlivVDv5OSMntOt+
         lzNA6BX5sKwEmpr23bgNk0lvB3az2kMup4lJwCbSaAcyNvLIbAjlGb9oQCUWR71nPNCa
         mHYtpHBBUGOnIVksX/mCfbA/8LV09Q+p9+W6Ygr/HtXBdUuctcw7tnITv1/0fRdcn157
         PcCBkWdNC8wKAFfUY7YApP9djnZJChVP4mJpLYqOmVdZMPtT8yOoKhyj7OTNzhUsWezN
         njIQ==
X-Forwarded-Encrypted: i=2; AJvYcCWFNC/Enw0M8ZcA2SYOq+0C6rBIYIFa4AS9gcAoW3hlcDBsg/0ASeji+iMQ/5SNnbkXu/egcDgI4rO37JpYAZlwFwJBwuIPqA==
X-Gm-Message-State: AOJu0YwAhrNY9Ob3P7UC40nTNXlP3ys+ygarOaaIYL2hh/TTLYSB7GYT
	T48yVeLHPbzaLnZT8BEpGAb4Ec6uEzaK5z2amdJMwaQo2IsdLRdi
X-Google-Smtp-Source: AGHT+IF1BGDkOGcoKtyXULttGPK2VTGW+I+x0z2R9HnWomplIdFeGNdzM0W6L/vNUHMpRxvLabBDxA==
X-Received: by 2002:a2e:bc1a:0:b0:2ee:d55c:255f with SMTP id 38308e7fff4ca-2f03c7ce3d8mr57399911fa.7.1722245773099;
        Mon, 29 Jul 2024 02:36:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2122:b0:2f0:1ef0:8b9 with SMTP id
 38308e7fff4ca-2f03aa8a63cls577731fa.2.-pod-prod-04-eu; Mon, 29 Jul 2024
 02:36:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDvbN7DefnGy0H0GX5yAYLZ5iBPBIbi7ZmxJkO76WkYw/RuWH6XC8l8GfWxEQVSyMgViOjU4UMeZ5clB6HNi6loDdWwJXLID20EQ==
X-Received: by 2002:a05:651c:446:b0:2ef:290e:5b47 with SMTP id 38308e7fff4ca-2f12edfd7aamr44617681fa.15.1722245771090;
        Mon, 29 Jul 2024 02:36:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722245771; cv=none;
        d=google.com; s=arc-20160816;
        b=sr+fb4Pf1S6IK64Zz/uFEYye+PAp1SyxjgDgp2vbo2nHrIkCc/DOkf/r+IwpozP2yy
         Ko/gKcuxfTuTf/MPJkelGu0T7jMI8s/hqOEOozRN/r5OnAqJC1OakNHBETOP0gEdgpJ1
         8O8quRsPMYF97dFvtDAe88/dAOJUntXGaNUtsHM12XDeQU6Go4F7AB3JIIRYHRqgbd00
         Cdhb42g2AJhZ/v0SY+ZOgJvFJ6+PBOhvK+mlaxuvJlDc7aX3mHFTsEkU1O1MF+cHdbSJ
         ug7zMaEN3kpCvfMFeYrSG8mdhR92yEjdVDtke7GP42/1t4wK2QHhPjhGOccc7A2OZ7up
         nYlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+6d72j4m/DpNbImW85Yz95FX2UHa2MMdK+SLSOWiCuU=;
        fh=MBt8u/qFZI1AEiU+v61cXKVbHP9rOqx+rOiQzPsP1+4=;
        b=oUghS1EO8fkMJ9Vfjzf/PM6urxuj3yeU892x6GQ1Amc82PuX4hFeVMIvIc6d58bC1i
         fIfw83dJrOns+40wgLY16or2mlaePhG/tqSEgqRVedlAXQuQYLOiE9RRHufONrDiBm5i
         QlFNe3+lzjFuL03QOaLngIWNP6L6eJGagKdsPINcz62f4IU2MrnkMc04NUe3Sx4kYM0z
         B6hGB6DNpVkAyNG60SVqbJXafo66UHO8T3wpy7MR7QLnIFj+U/eaX/0r0jPdqTEfCW+1
         QXBwxn3XITTD+J+IeYVL4VdQ9VYR30j2eEVd/eqPqVVUNVyQhcMKLUJPejdLTu7K6+Ub
         DcsQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NlJcQuGQ;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36b36771c4fsi179891f8f.2.2024.07.29.02.36.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jul 2024 02:36:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id 4fb4d7f45d1cf-5a869e3e9dfso9348a12.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2024 02:36:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU9WE86PtQZ/u6Qet+ly5mK13lpNmDYOm0knrwo5XOVbpveHgmkx/GAfKHOxPaQQdJL4kf5N034bR30+UJvkTIStwtanAjO15Ms/A==
X-Received: by 2002:a05:6402:354d:b0:57c:c3a7:dab6 with SMTP id
 4fb4d7f45d1cf-5b033c83768mr260452a12.3.1722245769876; Mon, 29 Jul 2024
 02:36:09 -0700 (PDT)
MIME-Version: 1.0
References: <20240725-kasan-tsbrcu-v3-2-51c92f8f1101@google.com> <202407291014.2ead1e72-oliver.sang@intel.com>
In-Reply-To: <202407291014.2ead1e72-oliver.sang@intel.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Jul 2024 11:35:32 +0200
Message-ID: <CAG48ez3H8VoesiWPoSzcnHHYEADndmK9Nwae=JL3d6JfdpjNUg@mail.gmail.com>
Subject: Re: [PATCH v3 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: kernel test robot <oliver.sang@intel.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=NlJcQuGQ;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Mon, Jul 29, 2024 at 6:37=E2=80=AFAM kernel test robot <oliver.sang@inte=
l.com> wrote:
> kernel test robot noticed "WARNING:possible_circular_locking_dependency_d=
etected" on:
>
> commit: 17049be0e1bcf0aa8809faf84f3ddd8529cd6c4c ("[PATCH v3 2/2] slub: I=
ntroduce CONFIG_SLUB_RCU_DEBUG")
> url: https://github.com/intel-lab-lkp/linux/commits/Jann-Horn/kasan-catch=
-invalid-free-before-SLUB-reinitializes-the-object/20240726-045709
> patch link: https://lore.kernel.org/all/20240725-kasan-tsbrcu-v3-2-51c92f=
8f1101@google.com/
> patch subject: [PATCH v3 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
[...]
> [  136.014616][    C1] WARNING: possible circular locking dependency dete=
cted

Looking at the linked dmesg, the primary thing that actually went
wrong here is something in the SLUB bulk freeing code, we got multiple
messages like:

```
 BUG filp (Not tainted): Bulk free expected 1 objects but found 2

 --------------------------------------------------------------------------=
---

 Slab 0xffffea0005251f00 objects=3D23 used=3D23 fp=3D0x0000000000000000
flags=3D0x8000000000000040(head|zone=3D2)
 CPU: 1 PID: 0 Comm: swapper/1 Not tainted 6.10.0-00002-g17049be0e1bc #1
 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS
1.16.2-debian-1.16.2-1 04/01/2014
 Call Trace:
  <IRQ>
  dump_stack_lvl+0xa3/0x100
  slab_err+0x15a/0x200
  free_to_partial_list+0x2c9/0x600
[...]
  slab_free_after_rcu_debug+0x169/0x280
[...]
  rcu_do_batch+0x4a4/0xc40
  rcu_core+0x36e/0x5c0
  handle_softirqs+0x211/0x800
[...]
  __irq_exit_rcu+0x71/0x100
  irq_exit_rcu+0x5/0x80
  sysvec_apic_timer_interrupt+0x68/0x80
  </IRQ>
  <TASK>
  asm_sysvec_apic_timer_interrupt+0x16/0x40
 RIP: 0010:default_idle+0xb/0x40
 Code: 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
90 90 90 90 90 90 90 90 90 90 eb 07 0f 00 2d 17 ae 32 00 fb f4 <fa> c3
cc cc cc cc cc 66 66 66 66 66 66 2e 0f 1f 84 00 00 00 00 00
 RSP: 0018:ffff888104e5feb8 EFLAGS: 00200282
 RAX: 4c16e5d04752e300 RBX: ffffffff813578df RCX: 0000000000995661
 RDX: 0000000000000001 RSI: 0000000000000004 RDI: ffffffff813578df
 RBP: 0000000000000001 R08: ffff8883aebf6cdb R09: 1ffff11075d7ed9b
 R10: dffffc0000000000 R11: ffffed1075d7ed9c R12: 0000000000000000
 R13: 1ffff110209ca008 R14: ffffffff87474e68 R15: dffffc0000000000
  ? do_idle+0x15f/0x400
  default_idle_call+0x6e/0x100
  do_idle+0x15f/0x400
  cpu_startup_entry+0x40/0x80
  start_secondary+0x129/0x180
  common_startup_64+0x129/0x1a7
  </TASK>
 FIX filp: Object at 0xffff88814947e400 not freed
```

Ah, the issue is that I'm NULL as the tail pointer to do_slab_free()
instead of passing in the pointer to the object again. That's the
result of not being careful enough while forward-porting my patch from
last year, it conflicted with vbabka's commit 284f17ac13fe ("mm/slub:
handle bulk and single object freeing separately")... I'll fix that up
in the next version.


I don't think the lockdep warning is caused by code I introduced, it's
just that you can only hit that warning when SLUB does printk...

> The kernel config and materials to reproduce are available at:
> https://download.01.org/0day-ci/archive/20240729/202407291014.2ead1e72-ol=
iver.sang@intel.com

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez3H8VoesiWPoSzcnHHYEADndmK9Nwae%3DJL3d6JfdpjNUg%40mail.gmai=
l.com.
