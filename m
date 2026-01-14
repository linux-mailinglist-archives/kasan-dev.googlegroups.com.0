Return-Path: <kasan-dev+bncBAABBU4ST3FQMGQEBIQAUAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D7F9D1EB01
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 13:17:25 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-6610bb06cd5sf241612eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 04:17:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768393044; cv=pass;
        d=google.com; s=arc-20240605;
        b=VAEB/oY6ahlzpZKnyvcY3Qy2fe2lX7xlFFSn+S92Y6k2Z1dUVdBIZD9BF7mf+aZKh7
         qeorqhJmg8G8XU1OcYNAQk+3VtMuH0bK1jbNkZ/CHUizNBVvjUZU009fMw9Jd7PvDLuN
         +VcYEvNWyPa0JytjD1QoKvzVH5gpXj/i6p6sjfYjGgG3FW5JgUZNn9In8m3ooUBG/fRZ
         +NsG9JEHwdgOhLHxLcGOCSxV4c+6bikf7oLzJrmU6AqpZLYQnowEylQF/gpREpzb2nFt
         toIO4t2/YCeOA+ym96GKUD/1ure630/3MMBa9KNe/spL1DO5ao2MfjY29+eFNFTbGUny
         EIGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=HZPXFr7V5xVyNyzBsIs7wM6wbYaLBzrqIzNWD7OLBPU=;
        fh=F5NEqNzXssCqfgKb9hZp38RGV08qc1VfhbpHTGAIKbI=;
        b=By9EhTFRAOzsLpPgs5sYqAZXesMWwH8ElytEcN8sIklXQQBJmut7sKJZctIzD1CWZi
         C2ss/YlBzdJGh1Arp10WtREW5UzZ/2RvKlKt1D69NndJOtLQC3NvM9xF7G8yjA1UCcCM
         g2WC/PeLf6gbe852C5vKYEWY5bs94RpzKwImjYflAKjSx2QtP65kX4qIS6HnquQEc8ce
         eWF/42gWtbuFvrIa7oBYSPMPC8lV4zlVdNTzHW9+2pyO1lKysnfC7EK4q3DGoT5gQseR
         4cvzSMrdNUV9cmP5FZsMy5h86UdSahVcydcXYJUKK7cAeqIGuJG33DMF9HXhNzmbVbIa
         Whuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="KlGVeJ/m";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768393044; x=1768997844; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=HZPXFr7V5xVyNyzBsIs7wM6wbYaLBzrqIzNWD7OLBPU=;
        b=HnZem02hUgsCdeBP9F4RD2cTKkaCm/1oUJVKoZDSowYuBNbwfCs96J4a7ovWaDDTkW
         DpBCuxRwfRC/zU7M3eI0mX67ZgKZf5mElQ2BhBz61wHv/6s6tD00DchWoxnjsH+NAkMV
         yJKow6dd+p4zvRd7Wf7lGj639aWH1ct5giHHAZOcRq1pRnC2JrgdRJyfw1SgbPlBdDxL
         bVlU92LrsCnL/d7Wn5tF2QR4iHGRSKdQFVh2pW1Gm6YF1XDJN+h18YQHveuwA6TXl8JV
         6qhtp7i1BJqXs5SLzKLSO8kIVolHpQCcMHKoFWRxFKkX/Rt55MBUP0bX3VWUs8pdlAEo
         d1Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768393044; x=1768997844;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=HZPXFr7V5xVyNyzBsIs7wM6wbYaLBzrqIzNWD7OLBPU=;
        b=k3WEERWsGrFrkK5z1YdQ1P3R+gBExiR63OQeJuWJ/u7h8lJ7q0WLJXphUSW8fN+tW1
         qefn9/d4Z9uhKxSYbsNJKRDswonfu+NxwxjMezMVpWP9rrvG4WsDqdqkCs2/CvsLnTzG
         zv1lVXEf2FaSA5Wmb3MfJnJCvVlD1RI8Mdb5Mpo9JzUXH79YLz1VZZNCwysWBpkiplXL
         Cq7qckQgV16ioyFKxI/gpO10GGHAAT/jx2PIhd8G7LXSYhMDv7pOTlln0JiSroKi39hP
         MgcdvLhhAA5+Y2Inmcq70NGIzFxhY0jczqTlMZBzGhjwJMHc3AdAUHkvQMCq3WsOrBSP
         7q9Q==
X-Forwarded-Encrypted: i=2; AJvYcCV8jbWRs7PTzEdR5DkAQlsjR6gO1guz/4RJDPG3eUkn7A7NnqFhOUHkoMb2c1VjyNy6mIej/w==@lfdr.de
X-Gm-Message-State: AOJu0YxYUrC0UhzNKtZKrXKmmc3TqMktdB459AucwfzadRsOQlysOaB5
	6+8oVo7c4V2yIsPgG/TLt5jJfN20SCDQ715crHNH/hhsd5oSTpVWqppB
X-Received: by 2002:a05:6820:1508:b0:659:9a49:900d with SMTP id 006d021491bc7-66102da9a4dmr1488848eaf.58.1768393043660;
        Wed, 14 Jan 2026 04:17:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GWGgFcoHTtzF0VoJXpE0ieFA3BIYthT/8dTouXR6TevQ=="
Received: by 2002:a05:6820:6dc6:b0:65b:243c:21 with SMTP id
 006d021491bc7-65f473cff98ls4606878eaf.1.-pod-prod-03-us; Wed, 14 Jan 2026
 04:17:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUxffMtNGemHghy+ElyojuAZGzeIyX4ywxRdVqdKim4+X2qJWjrjoYQFP/8HN0CVgpz+/f8P2PUwjA=@googlegroups.com
X-Received: by 2002:a05:6830:268f:b0:7cf:cc2c:1d9f with SMTP id 46e09a7af769-7cfcc2c22e7mr1058913a34.32.1768393042736;
        Wed, 14 Jan 2026 04:17:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768393042; cv=none;
        d=google.com; s=arc-20240605;
        b=OKUhF5ALOWi664fkR1r/Bbh6oUo5OhTMKoBJMYMMYQ9paf/rxmQps05eU1DRBeLPW3
         2VfjSu30qdndvgOPjQJff53ir98jFR2I58JLktBxHoqPAZFTC054TUiQMKQ31IdUn+tv
         GkgB3QaTM4I+v3WDCixVQH1B9twhbI50gv/LV7811o2TkmXnLAfKH0PUysy3FaATmzlG
         FCbaRWiZPEPesGmzzSgFcxjZZ+ay4f83rt+55+7tFWJwQK7l/lm9SBPwOcP0XnkYrW6Z
         aY8G5ToKpmRxn95xkYWb1Dhci3xmQrXNjyLIFv3GnTwuiEeoDCZDODMN+Z2kJmfVFjRB
         cb6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=38Vfj0jf5OEFbTnSianKjy7lCeGnbxOyBRt1UQTdjUY=;
        fh=zy19ssU6U0uRgKNDFS3cNo9Vz5eG6KGYyKDtjiKSu+w=;
        b=Y1cUCJ5oxF5VyCC3HUoOvqpWZTGPNVHYrY7ECWWKF7H8Bhh1t5555DGaczM58YILoT
         1yBBWLithaZ29KAKoR1yQT/7h+wbTJvbz/6Pvyw0jJbBH0FQqa8LgJBS7DRbDDRFEStY
         g+dg4G0jMGB2HoNdkQ/zGqt3ClruZflAxwWSEz2wPr7+0DbmTqoDcGGzk6/YVkVh0zGO
         MUO+1LX1Fwn5aKrRMIHLlrhS6o6pmj+ecINmlfgStc/Jg41zuWLqw4c0hagzdkOXHaa+
         rwTcUNrJTH5aEPP1/BlIe4WQ5eCydnvqi/HTqpwUUERKslndZimOOG/IBmI/rfp45MvM
         ps2A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b="KlGVeJ/m";
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24416.protonmail.ch (mail-24416.protonmail.ch. [109.224.244.16])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7ce48200744si1045973a34.7.2026.01.14.04.17.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Jan 2026 04:17:22 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) client-ip=109.224.244.16;
Date: Wed, 14 Jan 2026 12:17:13 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, =?utf-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, Uladzislau Rezki <urezki@gmail.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, joonki.min@samsung-slsi.corp-partner.google.com, stable@vger.kernel.org
Subject: Re: [PATCH 1/2] mm/kasan: Fix KASAN poisoning in vrealloc()
Message-ID: <aWd2wquw1aEB2rON@wieczorr-mobl1.localdomain>
In-Reply-To: <20260113191516.31015-1-ryabinin.a.a@gmail.com>
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com> <20260113191516.31015-1-ryabinin.a.a@gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: bf1405530f43e5d2b345f5d47b7d43e403f0b146
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b="KlGVeJ/m";       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

Tested in generic and sw_tags modes. Compiles and runs okay with and withou=
t my
KASAN sw tags patches on x86. Kunit tests also seem fine.

Tested-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

On 2026-01-13 at 20:15:15 +0100, Andrey Ryabinin wrote:
>A KASAN warning can be triggered when vrealloc() changes the requested
>size to a value that is not aligned to KASAN_GRANULE_SIZE.
>
>    ------------[ cut here ]------------
>    WARNING: CPU: 2 PID: 1 at mm/kasan/shadow.c:174 kasan_unpoison+0x40/0x=
48
>    ...
>    pc : kasan_unpoison+0x40/0x48
>    lr : __kasan_unpoison_vmalloc+0x40/0x68
>    Call trace:
>     kasan_unpoison+0x40/0x48 (P)
>     vrealloc_node_align_noprof+0x200/0x320
>     bpf_patch_insn_data+0x90/0x2f0
>     convert_ctx_accesses+0x8c0/0x1158
>     bpf_check+0x1488/0x1900
>     bpf_prog_load+0xd20/0x1258
>     __sys_bpf+0x96c/0xdf0
>     __arm64_sys_bpf+0x50/0xa0
>     invoke_syscall+0x90/0x160
>
>Introduce a dedicated kasan_vrealloc() helper that centralizes
>KASAN handling for vmalloc reallocations. The helper accounts for KASAN
>granule alignment when growing or shrinking an allocation and ensures
>that partial granules are handled correctly.
>
>Use this helper from vrealloc_node_align_noprof() to fix poisoning
>logic.
>
>Reported-by: Maciej =C5=BBenczykowski <maze@google.com>
>Reported-by: <joonki.min@samsung-slsi.corp-partner.google.com>
>Closes: https://lkml.kernel.org/r/CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm0=
8oLO3odYFrA@mail.gmail.com
>Fixes: d699440f58ce ("mm: fix vrealloc()'s KASAN poisoning logic")
>Cc: stable@vger.kernel.org
>Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
>---
> include/linux/kasan.h |  6 ++++++
> mm/kasan/shadow.c     | 24 ++++++++++++++++++++++++
> mm/vmalloc.c          |  7 ++-----
> 3 files changed, 32 insertions(+), 5 deletions(-)
>
>diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>index 9c6ac4b62eb9..ff27712dd3c8 100644
>--- a/include/linux/kasan.h
>+++ b/include/linux/kasan.h
>@@ -641,6 +641,9 @@ kasan_unpoison_vmap_areas(struct vm_struct **vms, int =
nr_vms,
> 		__kasan_unpoison_vmap_areas(vms, nr_vms, flags);
> }
>=20
>+void kasan_vrealloc(const void *start, unsigned long old_size,
>+		unsigned long new_size);
>+
> #else /* CONFIG_KASAN_VMALLOC */
>=20
> static inline void kasan_populate_early_vm_area_shadow(void *start,
>@@ -670,6 +673,9 @@ kasan_unpoison_vmap_areas(struct vm_struct **vms, int =
nr_vms,
> 			  kasan_vmalloc_flags_t flags)
> { }
>=20
>+static inline void kasan_vrealloc(const void *start, unsigned long old_si=
ze,
>+				unsigned long new_size) { }
>+
> #endif /* CONFIG_KASAN_VMALLOC */
>=20
> #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
>diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
>index 32fbdf759ea2..e9b6b2d8e651 100644
>--- a/mm/kasan/shadow.c
>+++ b/mm/kasan/shadow.c
>@@ -651,6 +651,30 @@ void __kasan_poison_vmalloc(const void *start, unsign=
ed long size)
> 	kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
> }
>=20
>+void kasan_vrealloc(const void *addr, unsigned long old_size,
>+		unsigned long new_size)
>+{
>+	if (!kasan_enabled())
>+		return;
>+
>+	if (new_size < old_size) {
>+		kasan_poison_last_granule(addr, new_size);
>+
>+		new_size =3D round_up(new_size, KASAN_GRANULE_SIZE);
>+		old_size =3D round_up(old_size, KASAN_GRANULE_SIZE);
>+		if (new_size < old_size)
>+			__kasan_poison_vmalloc(addr + new_size,
>+					old_size - new_size);
>+	} else if (new_size > old_size) {
>+		old_size =3D round_down(old_size, KASAN_GRANULE_SIZE);
>+		__kasan_unpoison_vmalloc(addr + old_size,
>+					new_size - old_size,
>+					KASAN_VMALLOC_PROT_NORMAL |
>+					KASAN_VMALLOC_VM_ALLOC |
>+					KASAN_VMALLOC_KEEP_TAG);
>+	}
>+}
>+
> #else /* CONFIG_KASAN_VMALLOC */
>=20
> int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
>diff --git a/mm/vmalloc.c b/mm/vmalloc.c
>index 41dd01e8430c..2536d34df058 100644
>--- a/mm/vmalloc.c
>+++ b/mm/vmalloc.c
>@@ -4322,7 +4322,7 @@ void *vrealloc_node_align_noprof(const void *p, size=
_t size, unsigned long align
> 		if (want_init_on_free() || want_init_on_alloc(flags))
> 			memset((void *)p + size, 0, old_size - size);
> 		vm->requested_size =3D size;
>-		kasan_poison_vmalloc(p + size, old_size - size);
>+		kasan_vrealloc(p, old_size, size);
> 		return (void *)p;
> 	}
>=20
>@@ -4330,16 +4330,13 @@ void *vrealloc_node_align_noprof(const void *p, si=
ze_t size, unsigned long align
> 	 * We already have the bytes available in the allocation; use them.
> 	 */
> 	if (size <=3D alloced_size) {
>-		kasan_unpoison_vmalloc(p + old_size, size - old_size,
>-				       KASAN_VMALLOC_PROT_NORMAL |
>-				       KASAN_VMALLOC_VM_ALLOC |
>-				       KASAN_VMALLOC_KEEP_TAG);
> 		/*
> 		 * No need to zero memory here, as unused memory will have
> 		 * already been zeroed at initial allocation time or during
> 		 * realloc shrink time.
> 		 */
> 		vm->requested_size =3D size;
>+		kasan_vrealloc(p, old_size, size);
> 		return (void *)p;
> 	}
>=20
>--=20
>2.52.0
>

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
Wd2wquw1aEB2rON%40wieczorr-mobl1.localdomain.
