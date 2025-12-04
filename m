Return-Path: <kasan-dev+bncBAABBNFUY7EQMGQEZV46PDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id D667CCA5086
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 20:00:05 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-477771366cbsf8700865e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 11:00:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764874805; cv=pass;
        d=google.com; s=arc-20240605;
        b=ffpCzILn9frXs8D2cmpFuq4ISyTbR8GbFI5LjkjIoZmhOBQcDpF3ShKbkA+/nPJK/j
         U1zDaoC4MkpfRSBu2ZjChpLlSF+0LuojO++s7/1oXrIMkOQ/azHrde9TcVnAqnkmQMGX
         uAopmCK+3dn7Ugqp4H1SCWcST6xbpEJlzIlAdkQ3oe+hBWFZCvbl6ywAywvbMODle3ok
         2yKSgH/b0G8XwaKeG7iNJfuSQ8VjcoQUyWP/EKNGtQIp1HEEFNDTmEGRpeG1AE98T/n7
         iszuatzHxLRs39fEfqfURlYx/0SP7yk2Yow1gcPellvqSqZ2GHyYE6oq5kuC7ujrNf96
         v2Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=eL/uZV662pjvjq7g9NMeFdjKkg2sLv3BLNPECsVz2iE=;
        fh=fasAM4v5wvzQG0XqQsUv0t0fRvE92yNwWWgD4Rrp6wE=;
        b=gQRDbzySo1X+aZStPYKFwer7ngtoE82zxCcduKh6akp0dRDlaV8vigw2Z7UT0TXROk
         dXrdTpR/zcGFgdkNpevTOwjuAKJ6I9dhQkQYK/Gj8KTlg4b5GKa6NawzKkkCIPS+VdPp
         M3Z5/slryHi5CoNPXw5TE9Fc3ibQ/v8vnPU9siRQ/R7TMsUBJ5KGLMQkkXwC1u8evliL
         PXK58OOA3LPwcEpLf5VSFvXP7sCijZQFV+7lAOeTsnx2VZ793yHBeI2nh1y5tjMvTjyd
         XPpbXYV/Ln/adbGcrKEz8ml5j7be+rvvS+SewSssxw8GsiRxs55ZX1hgjvBFXboHP0qu
         Aj6Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=ReCyGiNT;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.103 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764874805; x=1765479605; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=eL/uZV662pjvjq7g9NMeFdjKkg2sLv3BLNPECsVz2iE=;
        b=s/0okIPQ1rL/LT51SymlBdOycs3IhFbGPgmFcDwS9/2yFGMActSZFDDdtk1mvGz0ce
         u09uTYy9EsoqwtX9Onc55C4EG2QHUAYiCjMsGlatOPL0qW99gMh/QtIJhW42mrkY46Uz
         bYtr1vicbkqX7X3PkOwyAMb3KxP5tEIRmIuIT1MbkVJ8HV60RuHP4oOJwe6RWyWSmiEh
         d2Gk4RfUwb58AzODXpBjAWxwNXITjIZiNb/E7zGnGiC9LElC0vivFfyilQ8PyXcgSCYz
         YF+E+b9icgmcXbSjE/nVFSJhsjr9mmCZwgtvCuO0HbTeS7t14kva0b+oZ1d9Rtq0n5ni
         pcAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764874805; x=1765479605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=eL/uZV662pjvjq7g9NMeFdjKkg2sLv3BLNPECsVz2iE=;
        b=aZ/FOgicaI4fvlvfG/cfpfmNm4TK/yZc+ILdp+HKoTTtmhpBqoOrAg6c4YmIkvE4LV
         7uLPh1E+MEp+5KBBwtVpMh/OaAPGrvcVnyGoXtQsQo9Zg/KaTAFhawzac9HEbWtJH8BV
         QyB42ESJqOWz8K0p0NzuoIPxoveqxiKjfjZb8pQ8/+pM6EFlEO+IvyqWSHo4Seze4Nlj
         dThsfDF5zGGfF0tMGJu3/Lc78if95LqQr34bTc//Y2xYQKDIFMqS0jZlVJlQoAml5ngI
         JNZA7LSf4WJBhLah/C1UiCOSsIAnToCvvGEuETQ2erb7X9+2CGOJB8OgLWLZ6jVroINx
         Oybg==
X-Forwarded-Encrypted: i=2; AJvYcCX/eMpfYyADJiKpEgiFSS4wravUaxgHtFJjRQiAopb1bIZKBocSdz0+Rx+EjG67hmKWgtBI+g==@lfdr.de
X-Gm-Message-State: AOJu0YxSS5o4siRfp3zF95fJAiUnnFyABv2iwg7QdV8T9HijxDmTckb1
	2+KX9S/m+e6wUzkg/L9xms058rx22d6eWuwl8BpwNiZIy8DKnHdmq+8Y
X-Google-Smtp-Source: AGHT+IEw2PRZm0f78FQKa/Kn4o4RfEGRQZevPssuzJ4GOqLLJgbCDkMsFYLCG8oTxJJk2hqNbc9ZPg==
X-Received: by 2002:a05:600c:c491:b0:477:632c:5b91 with SMTP id 5b1f17b1804b1-4792af30e95mr87149055e9.16.1764874805119;
        Thu, 04 Dec 2025 11:00:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+awYVkdJmx9q0tPe7HJ4mqReJxAA7Tu6HKtTEDW9YcU7g=="
Received: by 2002:a05:6000:2583:b0:42b:52c4:6656 with SMTP id
 ffacd0b85a97d-42f7b2f4272ls602071f8f.2.-pod-prod-03-eu; Thu, 04 Dec 2025
 11:00:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUwa3lulThhtmUweDdhR09omYLM+f0FOotUn30qATFPWnf66bvrzf7S2I+x/tyWK5DHAqeGdbFl2kk=@googlegroups.com
X-Received: by 2002:a05:6000:288d:b0:429:ed90:91dd with SMTP id ffacd0b85a97d-42f7318fba9mr7491886f8f.6.1764874803066;
        Thu, 04 Dec 2025 11:00:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764874803; cv=none;
        d=google.com; s=arc-20240605;
        b=Ujb00IbGdBBz6gaKYdh8HhuEFTaLtv7BL3InTWtvzmUuwFvFvc68cmcWDfoetUNm5u
         8DKrw7ppFdrcWDR9yLSBTgBcujHBo0d54wxGjtqI/O8+HalW4KktGg/V7xPR9l2qz/O6
         6vf0nrVIMv31EJMz2RrHjRFSmJnWUlSDncoyxk/WMKnl4eDeMPz6fNdpttq+szrPrDAA
         z0ZoaQUolTkakz9GqLpCgvmz5wCtKOKYdimFc2enWCuIH8rvrbp2EXFB0570pV/Au8AN
         k/8/wT6I+/dJEMBW3VzhQXWTGuRfpsx8Esg/sT5Zdwjp9Twv/+cr5omaOX57Tmrkprii
         vWKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=bhwcCfVXLxvJTjdvRA/wCu8iamjahYD6lETVGfCcvog=;
        fh=u4G8fxakcqIyS4PhaeDPShJ+YDRtlSlDWUheelz7qHA=;
        b=cEa1t1AdueTVZuRuBQyeokgbJTCnJRlrAiQ7YSGIVYPleTdChUQDFeG/IGD8xPfZX+
         mi5jrO1nJDb7YvAwQrM0o/YlA2f7ymmmbEPClj9XgvjH/c+S7OC2itpSb7pUwDMJcxj3
         RgCV/XAE/2CGmENprxpyBIGOtqF1ro/DYfiGUh+nAGqqSLwaHkA2heWC0abeSTgA8zNq
         NwblvMFACNoAs6dcscrg6XexBuzID7+WJK5cjxJNu/glMkEpGdO/IfJJah0UnocRg9YR
         s1C09eNYyEQ02Zjdpd0dGPCy2WWYHLP/Hxqg1gTmPMAnSkINdMf2/Xh7cSuLW1bUZ3+Z
         Gd0Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=ReCyGiNT;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.103 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-43103.protonmail.ch (mail-43103.protonmail.ch. [185.70.43.103])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42f7ca42ce1si28707f8f.0.2025.12.04.11.00.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 11:00:03 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.103 as permitted sender) client-ip=185.70.43.103;
Date: Thu, 04 Dec 2025 18:59:55 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Danilo Krummrich <dakr@kernel.org>, Kees Cook <kees@kernel.org>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, jiayuan.chen@linux.dev, syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: [PATCH v3 1/3] mm/kasan: Fix incorrect unpoisoning in vrealloc for KASAN
Message-ID: <38dece0a4074c43e48150d1e242f8242c73bf1a5.1764874575.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1764874575.git.m.wieczorretman@pm.me>
References: <cover.1764874575.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: a4419e9b3fef3fe2260aceee3124e0bc104820b2
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=ReCyGiNT;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.103 as
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

From: Jiayuan Chen <jiayuan.chen@linux.dev>

Syzkaller reported a memory out-of-bounds bug [1]. This patch fixes two
issues:

1. In vrealloc the KASAN_VMALLOC_VM_ALLOC flag is missing when
   unpoisoning the extended region. This flag is required to correctly
   associate the allocation with KASAN's vmalloc tracking.

   Note: In contrast, vzalloc (via __vmalloc_node_range_noprof) explicitly
   sets KASAN_VMALLOC_VM_ALLOC and calls kasan_unpoison_vmalloc() with it.
   vrealloc must behave consistently =E2=80=94 especially when reusing exis=
ting
   vmalloc regions =E2=80=94 to ensure KASAN can track allocations correctl=
y.

2. When vrealloc reuses an existing vmalloc region (without allocating
   new pages) KASAN generates a new tag, which breaks tag-based memory
   access tracking.

Introduce KASAN_VMALLOC_KEEP_TAG, a new KASAN flag that allows reusing
the tag already attached to the pointer, ensuring consistent tag
behavior during reallocation.

Pass KASAN_VMALLOC_KEEP_TAG and KASAN_VMALLOC_VM_ALLOC to the
kasan_unpoison_vmalloc inside vrealloc_node_align_noprof().

[1]: https://syzkaller.appspot.com/bug?extid=3D997752115a851cb0cf36

Fixes: a0309faf1cb0 ("mm: vmalloc: support more granular vrealloc() sizing"=
)
Reported-by: syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/all/68e243a2.050a0220.1696c6.007d.GAE@googl=
e.com/T/
Signed-off-by: Jiayuan Chen <jiayuan.chen@linux.dev>
Co-developed-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 include/linux/kasan.h | 1 +
 mm/kasan/hw_tags.c    | 2 +-
 mm/kasan/shadow.c     | 4 +++-
 mm/vmalloc.c          | 4 +++-
 4 files changed, 8 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d12e1a5f5a9a..6d7972bb390c 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -28,6 +28,7 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
 #define KASAN_VMALLOC_INIT		((__force kasan_vmalloc_flags_t)0x01u)
 #define KASAN_VMALLOC_VM_ALLOC		((__force kasan_vmalloc_flags_t)0x02u)
 #define KASAN_VMALLOC_PROT_NORMAL	((__force kasan_vmalloc_flags_t)0x04u)
+#define KASAN_VMALLOC_KEEP_TAG		((__force kasan_vmalloc_flags_t)0x08u)
=20
 #define KASAN_VMALLOC_PAGE_RANGE 0x1 /* Apply exsiting page range */
 #define KASAN_VMALLOC_TLB_FLUSH  0x2 /* TLB flush */
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 1c373cc4b3fa..cbef5e450954 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -361,7 +361,7 @@ void *__kasan_unpoison_vmalloc(const void *start, unsig=
ned long size,
 		return (void *)start;
 	}
=20
-	tag =3D kasan_random_tag();
+	tag =3D (flags & KASAN_VMALLOC_KEEP_TAG) ? get_tag(start) : kasan_random_=
tag();
 	start =3D set_tag(start, tag);
=20
 	/* Unpoison and initialize memory up to size. */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 5d2a876035d6..5e47ae7fdd59 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -648,7 +648,9 @@ void *__kasan_unpoison_vmalloc(const void *start, unsig=
ned long size,
 	    !(flags & KASAN_VMALLOC_PROT_NORMAL))
 		return (void *)start;
=20
-	start =3D set_tag(start, kasan_random_tag());
+	if (unlikely(!(flags & KASAN_VMALLOC_KEEP_TAG)))
+		start =3D set_tag(start, kasan_random_tag());
+
 	kasan_unpoison(start, size, false);
 	return (void *)start;
 }
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 798b2ed21e46..22a73a087135 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4176,7 +4176,9 @@ void *vrealloc_node_align_noprof(const void *p, size_=
t size, unsigned long align
 	 */
 	if (size <=3D alloced_size) {
 		kasan_unpoison_vmalloc(p + old_size, size - old_size,
-				       KASAN_VMALLOC_PROT_NORMAL);
+				       KASAN_VMALLOC_PROT_NORMAL |
+				       KASAN_VMALLOC_VM_ALLOC |
+				       KASAN_VMALLOC_KEEP_TAG);
 		/*
 		 * No need to zero memory here, as unused memory will have
 		 * already been zeroed at initial allocation time or during
--=20
2.52.0


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3=
8dece0a4074c43e48150d1e242f8242c73bf1a5.1764874575.git.m.wieczorretman%40pm=
.me.
