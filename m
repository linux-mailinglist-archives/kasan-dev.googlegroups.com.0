Return-Path: <kasan-dev+bncBAABBJNSUTFQMGQEDLKLV6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id D21ADD25CE9
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 17:43:18 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-4801da6f5c9sf2052695e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 08:43:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768495398; cv=pass;
        d=google.com; s=arc-20240605;
        b=btaF3n5Ls2icjvu+26O2gzWqrFIoYyEfuMrQDiawdLB62oGZy/5hL31ry4lWe5Sw7y
         quQ+gcOkTqIwtI1W+98ckW9fKFSBzounReCrnOOLCwAcPhhyMlIWAlujh3wUMknz8LHy
         3HEx2AFoPIV4tRF1XyGd2fkbb3/mrO7Pjuoq6+OhKSFvXKizBypsb/ZwA3baKruzz9pV
         aHTATqD61h9DYLJYKyYDXM4cD2AYvuywhDSmsBefZ2rDM4qOI0NsjAqjm2BUYpnOqrrr
         v6efLCvXLfUd2SedEYcrmByYOmzQxFm4n0EBatjRl+hXehmzkYLH/FNGLaHTDFrWCqlx
         AONQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=MFg+lJVKHeWIen8nggYojtVkvhkgHdF0EOI32F2y55s=;
        fh=E1uJ9WX7mV+7i29q0beerOtWRKSBTzt92IFfwIE9tDU=;
        b=fYkE/2SL1zKC4K4FjnC7VzU4GVMu7dXfVCFgEOz1PGHqu+EfHgw/+sFoIBdkhkj5Eh
         sEjS0sPpHKHoAjImSKtI/OKvTkJxmscWA6xynvF4FtsEM84ZNC87xFIi6P57qToPXv1r
         gAvSjlxrVgivXo2dsaYGlpL0hhpMZLx1NI7LvirarrM3F805aiMFBQp/ZStl54sKJAlX
         0uDP2Gc1fWJiq4wIkaiu1801sS4TSIbZVFcVf0+g3qp/+EM4LziVb9wnYeCp5RYZHmYs
         jNzIHns9tSCcR/HnuOvh++FNSeX13w99THj6SrG3s6GzLMBYOnOdsrMk04wXLesfzrXN
         Ae3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=lAZsD8D3;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768495398; x=1769100198; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=MFg+lJVKHeWIen8nggYojtVkvhkgHdF0EOI32F2y55s=;
        b=Nqupm80Lgqx2SJecC8w1otjMGkDiyyCQ35/A2yM/SkbOs819fNSJFAayMwkfxTtYvB
         hEg8mQY0iTire6Z+BH/H1bBiQ/6ByGa4BXIQvRbkn4hsvs3PZrc3J51nB2+P0/hKbhEi
         TYOYN4gMC7cRp0gCZl/GtdyyJ30fDJCiu/bVq1fKE58f/XRMjhNRT5wom8z1ELmxi1nY
         MOy4iMxMy0jvxv96Xx6+IwRo7G0pg6tQvtbJ0KD+ZkWdpymvfsrJIUvTjBGeTCfKU/K4
         s8msVO5wI92gXZ1+1cslMUUNCTsO5qScZRF5LHv03zkZD8T7Yo8yCTo28bb4tubfX+tO
         jHOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768495398; x=1769100198;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=MFg+lJVKHeWIen8nggYojtVkvhkgHdF0EOI32F2y55s=;
        b=kBoZowkVXfPzmtM6kN4/XOLCfRT+Lx+hnEpqgj3HSiBOCjLuot3/1X1/sN3ll4bs0H
         myWVL00gMXouZHgI3MHxuUItJhoTAEf1H8iaEWXnGLy2pjZuG+MHJnCP+HkS46n0ou/7
         My46m0Ad2Sun5AmSfqqPYwuGTZZIPgpS2zRVwaVde+eRtBB7fi0wJoUa077ci7+l6Opp
         kiXqk0ztSTvodgmPwxftQtnqTWnPibFwv531M8JLlfaluVsMk7aUrrnZeglMF5MCnzNl
         JgTXTT+msQZXlJCRvS+RP7W7C8kpl0ByzhO9S8Dghxwk0c6bCOlkoN23UJ4/lDG+yqli
         70Xw==
X-Forwarded-Encrypted: i=2; AJvYcCUee96E/l3J84x2qScuQuf2xGZNEIq1vA2e3Pt2BOR41rTFlLXhYoXmBjx8qXZe7dAKoqEQrQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy8tzXcEyozNo7zPJ0sPjBMnYX1okPscDu9gweijU/vp3heUO6v
	qR89bu2FFexkxOoQp5SeKaYHzWY7RBwXTOi6OnuF04upojIyIlYEuwZU
X-Received: by 2002:a05:600c:1c15:b0:477:58af:a91d with SMTP id 5b1f17b1804b1-4801e35cff7mr4079145e9.5.1768495397951;
        Thu, 15 Jan 2026 08:43:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Gf6uzQNaGNi1ZE/If1OND1zAMsl+y2utaS+dT558BvWA=="
Received: by 2002:a05:6000:2484:b0:426:fc42:689f with SMTP id
 ffacd0b85a97d-435641701e9ls644612f8f.2.-pod-prod-05-eu; Thu, 15 Jan 2026
 08:43:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXK56d/aaNJBalQthiz8GUYjbHkECwrxqJR8ClgVzJn5uqr8DKim9yocgeCAD7FKan/dZW4hozZ6q0=@googlegroups.com
X-Received: by 2002:a05:6000:2407:b0:430:fced:90a with SMTP id ffacd0b85a97d-4342c4f70ebmr8563169f8f.16.1768495396166;
        Thu, 15 Jan 2026 08:43:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768495396; cv=none;
        d=google.com; s=arc-20240605;
        b=IPzzUaQBagrMF7PtEjFmJEFg5MySkRQxbNy94vIgtRRIckbcIAv9BHqosT/YaRvgwU
         0KzUXIMDEfuPQZ7wEweETIDBVtSI4rBLlo9naWs9KJ45QdiHXABz0jK3UYWetzHMpNHE
         5HtUt9y4T58fWONCgsHtyiU2NkgkDtxLr4yxZ/imtSyhnFLZd1Gh0de63gO0vRUyRyeO
         bsdvcum8gXevGK8jV4pCvvg1p0KsOg8cei/+owfO99OInekCHuPDSyzA8JmJYgGeqvnw
         GNO3wtBkNiHa1VTur/4qZ4skRK80twu8HxZfi98yewn8NvVS48nBR4ZdLZjbC45eu3ky
         ysFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=0mJ77Ei2Ao2nIh3bxf+lreguMZ0Ww1g/bobwuzi9ljs=;
        fh=h7y4lLUGVbT1Ds52fRLa9C4INAXfD90EjF47xC3gneA=;
        b=Z2TyMP+TF+mTzCUWOY+B2xEJFssapqZrrVN/DEAeDGK4hvwjHVSkBm6a0EMmilmnz1
         4mQWQoRFRWHIAY/aFU5RUTh0AER2l6hYoVQPkSIwtUs5g6Va7TyHQiAMiQuwoLmpWbY9
         HoGxXHdFmVnpOea/+SvXB4k8uFj5ghN71VdS+R8Nf1VSv5Y2J6gOXG40ZJADFPZjYOjl
         ehnb68VXQTEIhLZ84veUb1DJztX8HVSH0xtiJjQVybgtYL8QBlIOuTipNguGWAzsj32w
         HGADyTFG5NLJBkw6TV16ad/uzYvpd98kU0edj3cArd8FCzHFMeyvbxuPXI1Qj6kQaQwH
         h1oQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=lAZsD8D3;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10631.protonmail.ch (mail-10631.protonmail.ch. [79.135.106.31])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-435696fb216si935f8f.0.2026.01.15.08.43.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jan 2026 08:43:16 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) client-ip=79.135.106.31;
Date: Thu, 15 Jan 2026 16:43:08 +0000
To: Andrey Konovalov <andreyknvl@gmail.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH v8 13/14] x86/kasan: Logical bit shift for kasan_mem_to_shadow
Message-ID: <aWkVn8iY27APFYy_@wieczorr-mobl1.localdomain>
In-Reply-To: <CA+fCnZd4rJvKzdMPmpYmNSto_dbJ_v6fdNYv-13_vC2+bu-4bg@mail.gmail.com>
References: <cover.1768233085.git.m.wieczorretman@pm.me> <b1dcc32aa58fd94196885842e0e7f7501182a7c4.1768233085.git.m.wieczorretman@pm.me> <CA+fCnZd+ANJ2w4R7ww7GTM=92UGGFKpaL1h56iRMN2Lr14QN5w@mail.gmail.com> <aWfDiNl9-9bVrc7U@wieczorr-mobl1.localdomain> <CA+fCnZd4rJvKzdMPmpYmNSto_dbJ_v6fdNYv-13_vC2+bu-4bg@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 13c6233a9439a29467710c147956a9b472747181
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=lAZsD8D3;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as
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

On 2026-01-15 at 04:57:15 +0100, Andrey Konovalov wrote:
>On Wed, Jan 14, 2026 at 5:52=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> I'm a fan of trying to keep as much arch code in the arch directories.
>>
>> How about before putting a call here instead like:
>>
>>         if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
>>                 if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0=
ULL)) ||
>>                     addr > (unsigned long)kasan_mem_to_shadow((void *)(~=
0ULL)))
>>                         return;
>>         }
>>
>>         arch_kasan_non_canonical_hook()
>> There would be the generic non-arch part above (and anything shared that=
 might
>> make sense here in the future) and all the arch related code would be hi=
dden in
>> the per-arch helper.
>>
>> So then we could move the part below:
>>         if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) && IS_ENABLED(CONFIG_ARM64)=
) {
>>                 if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0=
xFFULL << 56)) ||
>>                     addr > (unsigned long)kasan_mem_to_shadow((void *)(~=
0ULL)))
>>                         return;
>>         }
>> to /arch/arm64.
>>
>> For x86 we'd need to duplicate the generic part into
>> arch_kasan_non_canonical_hook() call in /arch/x86. That seems quiet tidy=
 to me,
>> granted the duplication isn't great but it would keep the non-arch part =
as
>> shared as possible. What do you think?
>
>Sounds good to me too, thanks!

x86 was easy to do because the kasan_mem_to_shadow() was already in the
asm/kasan.h. arm64 took a bit more changes since I had to write the
arch_kasan_non_canonical_hook in a separate file that would import the
linux/kasan.h header in order to use kasan_mem_to_shadow(). Anyway below ar=
e the
relevant bits from the patch - does that look okay? Or would you prefer som=
e
different names/placements?

diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.=
h
index b167e9d3da91..16b1f2ca3ea8 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -17,6 +17,8 @@
=20
 asmlinkage void kasan_early_init(void);
 void kasan_init(void);
+bool __arch_kasan_non_canonical_hook(unsigned long addr);
+#define arch_kasan_non_canonical_hook(addr) __arch_kasan_non_canonical_hoo=
k(addr)
=20
 #else
 static inline void kasan_init(void) { }

diff --git a/arch/arm64/mm/Makefile b/arch/arm64/mm/Makefile
index c26489cf96cd..a122ea67eced 100644
--- a/arch/arm64/mm/Makefile
+++ b/arch/arm64/mm/Makefile
@@ -15,4 +15,6 @@ obj-$(CONFIG_ARM64_GCS)		+=3D gcs.o
 KASAN_SANITIZE_physaddr.o	+=3D n
=20
 obj-$(CONFIG_KASAN)		+=3D kasan_init.o
+obj-$(CONFIG_KASAN)		+=3D kasan.o
 KASAN_SANITIZE_kasan_init.o	:=3D n
+KASAN_SANITIZE_kasan.o		:=3D n
diff --git a/arch/arm64/mm/kasan.c b/arch/arm64/mm/kasan.c
new file mode 100644
index 000000000000..b94d5fb480ca
--- /dev/null
+++ b/arch/arm64/mm/kasan.c
@@ -0,0 +1,31 @@
+// SPDX-License-Identifier: GPL-2.0-only
+/*
+ * This file contains ARM64 specific KASAN code.
+ */
+
+#include <linux/kasan.h>
+
+bool __arch_kasan_non_canonical_hook(unsigned long addr) {
+	/*
+	 * For Software Tag-Based KASAN, kasan_mem_to_shadow() uses the
+	 * arithmetic shift. Normally, this would make checking for a possible
+	 * shadow address complicated, as the shadow address computation
+	 * operation would overflow only for some memory addresses. However, due
+	 * to the chosen KASAN_SHADOW_OFFSET values and the fact the
+	 * kasan_mem_to_shadow() only operates on pointers with the tag reset,
+	 * the overflow always happens.
+	 *
+	 * For arm64, the top byte of the pointer gets reset to 0xFF. Thus, the
+	 * possible shadow addresses belong to a region that is the result of
+	 * kasan_mem_to_shadow() applied to the memory range
+	 * [0xFF000000000000, 0xFFFFFFFFFFFFFFFF]. Despite the overflow, the
+	 * resulting possible shadow region is contiguous, as the overflow
+	 * happens for both 0xFF000000000000 and 0xFFFFFFFFFFFFFFFF.
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
+		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0xFFULL << 56)) |=
|
+		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
+			return true;
+	}
+	return false;
+}
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 9c6ac4b62eb9..146eecae4e9c 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
...
@@ -403,6 +409,13 @@ static __always_inline bool kasan_check_byte(const voi=
d *addr)
 	return true;
 }
=20
+#ifndef arch_kasan_non_canonical_hook
+static inline bool arch_kasan_non_canonical_hook(unsigned long addr)
+{
+	return false;
+}
+#endif
+
 #else /* CONFIG_KASAN */
=20
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 62c01b4527eb..1c4893729ff6 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -642,10 +642,19 @@ void kasan_non_canonical_hook(unsigned long addr)
 	const char *bug_type;
=20
 	/*
-	 * All addresses that came as a result of the memory-to-shadow mapping
-	 * (even for bogus pointers) must be >=3D KASAN_SHADOW_OFFSET.
+	 * For Generic KASAN, kasan_mem_to_shadow() uses the logical right shift
+	 * and never overflows with the chosen KASAN_SHADOW_OFFSET values. Thus,
+	 * the possible shadow addresses (even for bogus pointers) belong to a
+	 * single contiguous region that is the result of kasan_mem_to_shadow()
+	 * applied to the whole address space.
 	 */
-	if (addr < KASAN_SHADOW_OFFSET)
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0ULL)) ||
+		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
+			return;
+	}
+
+	if(arch_kasan_non_canonical_hook(addr))
 		return;

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
WkVn8iY27APFYy_%40wieczorr-mobl1.localdomain.
