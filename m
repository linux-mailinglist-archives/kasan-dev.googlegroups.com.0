Return-Path: <kasan-dev+bncBAABBR5FY3EQMGQESUSO3MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 89BF3CA3EA6
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 14:55:20 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-477cf25ceccsf10327645e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 05:55:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764856520; cv=pass;
        d=google.com; s=arc-20240605;
        b=b5v9AFbM8cKg+tp30V/FB4J8t05cCSck75DcfFXpeIgRAGBIxdSZMF9INIIDgh6Pge
         XvbtQ87OvABglv1SPz6kvfaMB/Ypn0J79Pr+p2wjCMEyfLfKFnazMDfInaJRYjzsM+fk
         ADydbqNXXA6/gh/P8E25MFjmBsxQcxFjDq8FQ5Oe86wQKoMb7IPOCGG9m+b43jpZmQ+E
         V+RQL8szpTZHLstRSUyA8DXc0N0MqCd4m+HaUXtjwtf3QL1Uhdo+UpVZ2e9jiE53RiJ3
         sGlJZ8EwKDQf61Z4T2Amqm0BOaVXi7Gv/bvNLas3iANJy49ninnUAPAibuHDN4XvdFJp
         0CDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=sQvqqT+rCg+FlNpj0rZWn7EvHKXy0zz4GnC9cNM5vwo=;
        fh=BEv+dH7Gg45weRqGugYkkqljo5Or/xwAUgV9rK1MPhc=;
        b=kukVmQn+EsQl/wjwa0Uj4zbn/PA3HA/bKHozLUoYcEMug08Yk24zV8vNUdLE3WlxfR
         yhgypPIJGgBreoN/rC1C7ihg2AV9DCS9Jf1HyWKl86+viHdO9/8eS4sNPfVz+t6Tf3Jc
         bMg7/8HlrCx9IGK7nSvs+lv6MM469C4nXEPuOfsYKKff6K8G0TiO0UXHZVL0aEFRozpy
         c1WjJJKbGDkx9Vttfu2Hzh9/C9rffRSEKh4wZ/2XbBNEcrwXEHe67t+PtzRFTkq1RZB4
         Nh7+CxUp84+cnrSPEMHIauhZ8jcD5zAzQCocwBqkHfJyEk5oW8jhTdICB3XXcErTSe5k
         Vohg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=Qcn4Mz1Q;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764856520; x=1765461320; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:from:to:cc:subject:date:message-id:reply-to;
        bh=sQvqqT+rCg+FlNpj0rZWn7EvHKXy0zz4GnC9cNM5vwo=;
        b=nD6ZwJ9wDkg8wo4zrDbrsabe5dO6h4XX9djQdxXinLSnoV3HVKCDcxQ3+QJ3k/DZ/G
         UINnfwCBakrGkARP8VaHIrSgFgDtHcG8DKIb0UeBWxfBI7Dc/h+rCmpOFJyDDjTFUV0z
         ndzav8KpJhoMtiMkOz1SXQlDqHR5qn5V2vXrziVpKkrdS3NKjKPr810xfYkUn3hm1qbd
         jt8Ld8Q2UL2am0dYihEfCqmQ5ei2En/srRsUantRmBtn6ZbCDI1/04Xjukpzib41+5KS
         w0BsyuJZKMtdV99BPKMrzDIxPjOXBTJPPH4E1H0AvQOlI4uEGDhKvpd9tSNHPyxb8b6O
         sMrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764856520; x=1765461320;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sQvqqT+rCg+FlNpj0rZWn7EvHKXy0zz4GnC9cNM5vwo=;
        b=afnnZLyy6cGs3DxnTbaQka0qEVu6/86SMYv1SCkyD9xdRoOQ3+ptommtySqcsZNqM9
         CzOrRMEHCDOnTd6f97TyOUp542TSHF0Y8+lPAcaaY3l6/d23qeVA0wy9ZVN1yBc1Sc7S
         GgJBPRaMoS1nqnrorHCjsaorzaRzr49aQbpJq5ufmTwpszkNAvQ3u+NOHzAFKM0IALJ/
         llF8xFhRkEvbZIF1FRmSkyg5nUOFDuh1FM0eaEYcdSqPFSygmwDYdwhyDR3XGV4oS7vJ
         qX657lnJaXpFRMtyw8YhYShqLIs8lbO0pWUp24eDQhMtOXlt7UltrtOy4l68JizKEUu0
         Yrdw==
X-Forwarded-Encrypted: i=2; AJvYcCUbIrzADL6L5zMiUHw0+BBaHvX6vj9x4fpFnBMAyrhdVqUN43YU77/H0OdAWiTWz85/U8bIKw==@lfdr.de
X-Gm-Message-State: AOJu0YyUxuec3DVkvEg5FtCsQhJzOaJamRM9qzdEWsRFX7jxG+i2iAF5
	FBrqbaDFwqCTFK3VpEeembshtU7tMtmZ9CnNVmaEEU5qgGg16jDMdWnG
X-Google-Smtp-Source: AGHT+IEt0FCs9b4WTRFGSnHKMy7/GPMvjsr3A5KUhMyxwTSOF5JAWDXGCg603YeXL7Qxg/Kos92rvA==
X-Received: by 2002:a05:600c:a45:b0:477:7bca:8b34 with SMTP id 5b1f17b1804b1-4792f244111mr26304825e9.6.1764856519712;
        Thu, 04 Dec 2025 05:55:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+az5ePPkrrv2mJe0WF/v/A2qvAqFg2SCoNXzpgOEHLyng=="
Received: by 2002:a05:600c:4509:b0:477:a1df:48a5 with SMTP id
 5b1f17b1804b1-4792fcda86dls7007505e9.2.-pod-prod-07-eu; Thu, 04 Dec 2025
 05:55:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX1K77GZ3noNXkBU4mAY13v+5vI5n3sutX2QSfsYWTgMf4cT1EPzeOgi3Ioejo2DKZGNDGnPor0DO8=@googlegroups.com
X-Received: by 2002:a05:600c:b8d:b0:477:6d96:b3e5 with SMTP id 5b1f17b1804b1-4792f244cdamr31541525e9.7.1764856517467;
        Thu, 04 Dec 2025 05:55:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764856517; cv=none;
        d=google.com; s=arc-20240605;
        b=lUIFG7PVe0arsCouLTdLGohYzx4t8WjG2Dz6LStDcipANUIH2MWu57woxbaFHFtD+k
         cJw6GxGVJ11JJC5PBY7E3M6TxOfupJOKBXfe+wQY9gtwbFpvoqF3FjjYhDWP4MDb5Kn6
         c44vGx1N5uK8APcgRRZAvGXGesHqJ9nFXRymKVEFf48CuMvg1tlEU5cV9nwqK6V3QjkP
         7fR4A9Q/p7mUFDDNTth7Nlc7/Qwr63RHrqK+Nr2Zxzr/ClFr7A+MY1+9WeRyb4yE3JHa
         edJ1wx5D3qBbMSdZurQaaMUbkESsbhNL8v0ffFxYDoBD2we/al1m9L1VytLXoUe/BNYt
         /2zQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:message-id
         :subject:cc:from:to:date:dkim-signature;
        bh=VqP9yp4hG0Ar5q/skyCmb0EwxkUlO46my0VVgJ5cvP8=;
        fh=i2t8z26IQvGJ7iyUcSnxdbY3r6+ayQmIC3mAzIr7w3s=;
        b=TDH3X9U++ttJDiYe1r/UFY/63s0VKP+/iRzDrmzE2RnBJ1nlEMaRKYGMVT+WBr0Kgo
         SqP/4zlsWN3vXOxa+v5ZQAFnboD1CyyHBStmsLLa6VfHQm+JFjRibd9RRs2PZD1IAqP6
         jRwKrIM2OF5MuyBYZVoa7OaALolHAW19QE+Y7AJj0Y/styh7DZdcIqXnjeKs9SLq7dM5
         bxWzfrvdNAvIf4qtlxeRCvdVlLe2LvaJuIIggW3jYiMD7HCMoxJfT36KO9sZVY+0TuSW
         Q8+1Y4nhYUmJORB5/ghEwsfDwUyDDqiGJYcw8O4RArwITC/M+gKmIvRUlqJKnehwAqCl
         g54w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=Qcn4Mz1Q;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106118.protonmail.ch (mail-106118.protonmail.ch. [79.135.106.118])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42f7cbd50f5si24503f8f.2.2025.12.04.05.55.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 05:55:17 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as permitted sender) client-ip=79.135.106.118;
Date: Thu, 04 Dec 2025 13:55:09 +0000
To: Jiayuan Chen <jiayuan.chen@linux.dev>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-mm@kvack.org, syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Danilo Krummrich <dakr@kernel.org>, Kees Cook <kees@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v1] mm/kasan: Fix incorrect unpoisoning in vrealloc for KASAN
Message-ID: <5o7owlr4ap5fridqlkerrnuvwwlgldr35gvkcf6df4fufatrr6@yn5rmfn54i62>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 03c4801ace3dadbee77e720f608d8e3c32b2382c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=Qcn4Mz1Q;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as
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

On 2025-12-03 at 02:05:11 +0000, Jiayuan Chen wrote:
>December 3, 2025 at 04:48, "Maciej Wieczor-Retman" <maciej.wieczor-retman@=
intel.com mailto:maciej.wieczor-retman@intel.com?to=3D%22Maciej%20Wieczor-R=
etman%22%20%3Cmaciej.wieczor-retman%40intel.com%3E > wrote:
>>=20
>> Hi, I'm working on [1]. As Andrew pointed out to me the patches are quit=
e
>> similar. I was wondering if you mind if the reuse_tag was an actual tag =
value?
>> Instead of just bool toggling the usage of kasan_random_tag()?
>>=20
>> I tested the problem I'm seeing, with your patch and the tags end up bei=
ng reset.
>> That's because the vms[area] pointers that I want to unpoison don't have=
 a tag
>> set, but generating a different random tag for each vms[] pointer crashe=
s the
>> kernel down the line. So __kasan_unpoison_vmalloc() needs to be called o=
n each
>> one but with the same tag.
>>=20
>> Arguably I noticed my series also just resets the tags right now, but I'=
m
>> working to correct it at the moment. I can send a fixed version tomorrow=
. Just
>> wanted to ask if having __kasan_unpoison_vmalloc() set an actual predefi=
ned tag
>> is a problem from your point of view?
>>=20
>> [1] https://lore.kernel.org/all/cover.1764685296.git.m.wieczorretman@pm.=
me/
>>=20
>
>Hi Maciej,
>
>It seems we're focusing on different issues, but feel free to reuse or mod=
ify the 'reuse_tag'.
>It's intended to preserve the tag in one 'vma'.
>
>I'd also be happy to help reproduce and test your changes to ensure the is=
sue I encountered
>isn't regressed once you send a patch based on mine.=20
>
>Thanks.

After reading Andrey's comments on your patches and mine I tried applying a=
ll
the changes to test the flag approach. Now my patches don't modify any vrea=
lloc
related code. I came up with something like this below from your patch. Jus=
t
tested it and it works fine on my end, does it look okay to you?

---
 include/linux/kasan.h | 1 +
 mm/kasan/hw_tags.c    | 3 ++-
 mm/kasan/shadow.c     | 4 +++-
 mm/vmalloc.c          | 6 ++++--
 4 files changed, 10 insertions(+), 4 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 03e263fb9fa1..068f62d07122 100644
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
index 1c373cc4b3fa..e6d7ee544c28 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -361,7 +361,8 @@ void *__kasan_unpoison_vmalloc(const void *start, unsig=
ned long size,
 		return (void *)start;
 	}
=20
-	tag =3D kasan_random_tag();
+	tag =3D (flags & KASAN_VMALLOC_KEEP_TAG) ? get_tag(start) :
+						 kasan_random_tag();
 	start =3D set_tag(start, tag);
=20
 	/* Unpoison and initialize memory up to size. */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 5d2a876035d6..6dd61093d1d5 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -648,7 +648,9 @@ void *__kasan_unpoison_vmalloc(const void *start, unsig=
ned long size,
 	    !(flags & KASAN_VMALLOC_PROT_NORMAL))
 		return (void *)start;
=20
-	start =3D set_tag(start, kasan_random_tag());
+	if (!(flags & KASAN_VMALLOC_KEEP_TAG))
+		start =3D set_tag(start, kasan_random_tag());
+
 	kasan_unpoison(start, size, false);
 	return (void *)start;
 }
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index ead22a610b18..c939dc04baa5 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4180,8 +4180,10 @@ void *vrealloc_node_align_noprof(const void *p, size=
_t size, unsigned long align
 	 * We already have the bytes available in the allocation; use them.
 	 */
 	if (size <=3D alloced_size) {
-		kasan_unpoison_vmalloc(p + old_size, size - old_size,
-				       KASAN_VMALLOC_PROT_NORMAL);
+		kasan_unpoison_vmalloc(p, size,
+				       KASAN_VMALLOC_PROT_NORMAL |
+				       KASAN_VMALLOC_VM_ALLOC |
+				       KASAN_VMALLOC_KEEP_TAG);
 		/*
 		 * No need to zero memory here, as unused memory will have
 		 * already been zeroed at initial allocation time or during

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5=
o7owlr4ap5fridqlkerrnuvwwlgldr35gvkcf6df4fufatrr6%40yn5rmfn54i62.
