Return-Path: <kasan-dev+bncBCT4XGV33UIBBOUW27DAMGQETBFUJEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id D6A18BA1ED4
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Sep 2025 01:07:40 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-2698b5fbe5bsf25040985ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Sep 2025 16:07:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758841659; cv=pass;
        d=google.com; s=arc-20240605;
        b=A0lX0pK99jpEa9QQcupglzstS0YZIXjtOZhxXdbR3oHIwSy7GYTSV7nIgU3bNXF1vS
         Bd0sL+TFWlNvHbHSPsjS0uwwspT8lYI+nat3uAN532TeGgF7p1z3IRT0ZUn8x6cvSZ1U
         uubIykrRjGRLs+Pg7aBXS3hpkLgoSoNV/TuOO1CV1/toujgVBkZ0ExbBkerb6ika9Vq7
         LeTISp+x3l4rMfONscE7p6q14NN9xEKiQsstswOI30GzcVwm0EmjpII0J46IiIW/enea
         W3dgPC5+yyT+H1YWbd3V8LPuqP5Dmi/NFUO8NVFZxCL5Px0ESewh1jvpV6QBjfPiw/ry
         k9mQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=oE4M3n7yAL6NnemeWWVB/84VaLkEKvu1hsBbqQcsoPg=;
        fh=+embVh3bcyJUUdvTymjVJiRs1fMQ0gknVQ+oxXsfHtQ=;
        b=WWqkL/j7NNuk2kD+qtCU7v8J7jtv/4ypDgCI6QQLb0s1onsVivHsTJBc94GM+4jWCR
         uvamDkq6aoHEPO1ajsoxWa64x83/HkjoVvCzyYCgNOlWAc3FfajrQXqo4EawCuanbeA5
         DTbNiM3cD+37PXNSq9eV40kwVa14R2H2lb6ifPhpeJJS9H48TDXjPc7T2hlK9lc0en9G
         P8DqonB8GvjjHDKcQfcuzYO66puvIZCvoXlX4JgA2vDzLj+OaiUUIdyq1F+xs5/WtBzc
         /gGjVitGyvf12sZyexjuztPa2HhqaeDhIC/rUWgSbnBdKaain5zzxp20MhCA9IKnAcJd
         pW8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=brT0Fr6Y;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758841659; x=1759446459; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oE4M3n7yAL6NnemeWWVB/84VaLkEKvu1hsBbqQcsoPg=;
        b=BJScqPDFPui/mVTghf25V5LN4NniIop6GMDx7X3Ee4WuxXC8/2VA9YJll3e1oJ5A8h
         xS3KH2SOYrQubNkUhr2Qrmffb+Gg657+PeSghNj7chZOuKL+6Mhrq0fLtHHLPUJOgkOp
         n8MmEJwN34HdWDo8iYFNNh+zKkSqA+ulHl6RAW7qz7RRHhsYHwYpgFBHhAQdTFampNYw
         AhIZssh/Ra2Pi8PLmy7CusJA6UXjSSEl6uXLNVqyrTRQIiIHJQJZFJHPfz0yDdCHP85o
         u4v0dZmcgHn5XoZ3Ff7j8e3EKaUIlvEYdweyEkFBT9SnI/+D4Z+xn04dqufIao8He3wU
         pKDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758841659; x=1759446459;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oE4M3n7yAL6NnemeWWVB/84VaLkEKvu1hsBbqQcsoPg=;
        b=ZVIHBv16ZTXXndpj/sJulQ6iQD7vyLWT5UDBZLDeuCpzfQ0BX7FzMhgzGDcXw+uQia
         kr7iAW6yJk+nWVpLkGAOFSQm8ATyJ5QESbnM+2S6B9vaj1TyHEAWLJaUvNATvRw2hbLH
         NjHCgSafGznQE3LCoK1ELz0p38YdFUfIUfmEQ5rwy7UbSpNitww4vTLSsRwQUULJWGp6
         2Qrwhe4WyHhr5IwKHQWd0z6WMTObOJFxsRhmPYERmL0dIPxBfhGpQKSz5sTm9rJn6O4n
         ssovopoj5wd2485+xuR4ig49jHhRRBaigwM55v95DaO8ISuz6zuHfjI9LqQZWdm7QcQM
         7GIQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUdbq/K8gTnpt0GSazflKK2zTcjp18PdxiOfASlFth1fVc2fuYvp1siE1leo1l8qROlgRvgEQ==@lfdr.de
X-Gm-Message-State: AOJu0YwLTo024kCFtAgPSOZ6lCkslCVgL3Q7Y1rJXA2Zt6x0j2mqE5rG
	PmmHWnHkjKP58QCweZz1SCgYrRMlagmnni7fn6hEI/WRDA6o1WHIfKH+
X-Google-Smtp-Source: AGHT+IHrG2wGvaAUSVjsFl0dC7W8NhUIe0xPOHuaV2d7F4nzHoGMX/UyByQegNu7a+ELxfOKmiER8w==
X-Received: by 2002:a17:903:1ac3:b0:27e:eea6:dffc with SMTP id d9443c01a7336-27eeea6e2b3mr5948605ad.41.1758841658891;
        Thu, 25 Sep 2025 16:07:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5HFKsJ7+RutUCResYpS8AOas64LQFAoQWfOOexiFumfA=="
Received: by 2002:a17:902:f385:b0:25d:b1dd:933c with SMTP id
 d9443c01a7336-27ed500d625ls15030155ad.0.-pod-prod-08-us; Thu, 25 Sep 2025
 16:07:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV8W4FIudXwmfi4fe+nIa0nP+O5DfSm4SqVrCz2/xhozuou7SiPnWeIm/r7t0Cyjtzh1GTODm88p2c=@googlegroups.com
X-Received: by 2002:a17:902:76c8:b0:267:af07:6526 with SMTP id d9443c01a7336-27ed4a66f88mr41301595ad.55.1758841657304;
        Thu, 25 Sep 2025 16:07:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758841657; cv=none;
        d=google.com; s=arc-20240605;
        b=V3Em1PisYktbByXV40wNzZk5ybXasumPRsacGyQxO4UDIFFYsvmP2PfU74lGu6GpP/
         rpuJnusLr5AtXMjnMKMgIEoM0oZB3YK4hb0T7mwLKUeUq5GtvonjBejn0zM297pSZetv
         2mXD1q3ZEJP46tHPUnqgYs1atJqNVLBoSeB/cmhWuctdZRGnKPOG03TLlxiheXG/imNa
         GH5jV7GoFWccLNzXzoVoZtm5ZyaVJxb5uUoLWpGNoHICObw7gpD8UyEMIa12AfuE99qF
         Wqxl3NSkU9/a9vXpmpsJZnyx/un1cnJ4v/036EPKkM5Gk61BB3z2yLW1LU3QDL/VOUpB
         DRfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=BeSxWx48aKNidsNnkG1cI4RNEijG5VTEYRv+7ldzcFg=;
        fh=NbF/6PLr7tEQquNY7qJq74sGcgEaUMMhCmoRepXcY0o=;
        b=D3xip+iAqzNrSHEW12jgvSKPgObmxd22cCgqZRrB2OwvJhjmJvtfxCKpCnjVYX+whY
         1ppA4JtiLdFObSWE7gY7pPbZETFrPXfAI8Wg90W64tHORXDKEnr1ujgLppbomEcbOW2N
         ij5N3y1ZEpfNOaGsYOBEQde+1iVj1bkoTtooPi55qGuTF+qfnQUGLVeDrUOraqFW/tWj
         x4Khqg6fbzSLc+j8tJGXeepV2lAgtmJT4Cr5XID6WrMFYi3SL9d7++P0c6alZNSnCfyu
         NENkLP2sASfm+bcv9/i4gMvpjYgLcMeL6uKedcAvwiWeuByOpD+bs3gE9Bc/92aRkh3U
         6tOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=brT0Fr6Y;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-27ed67a5467si1500195ad.3.2025.09.25.16.07.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Sep 2025 16:07:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id DBB2A440B0;
	Thu, 25 Sep 2025 23:07:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8587BC4CEF0;
	Thu, 25 Sep 2025 23:07:36 +0000 (UTC)
Date: Thu, 25 Sep 2025 16:07:36 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Balbir Singh <balbirs@nvidia.com>
Cc: agordeev@linux.ibm.com, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 ryabinin.a.a@gmail.com
Subject: Re: [PATCH] kasan: Fix warnings caused by use of
 arch_enter_lazy_mmu_mode()
Message-Id: <20250925160736.a8c65952370d66d1544f9309@linux-foundation.org>
In-Reply-To: <20250912235515.367061-1-balbirs@nvidia.com>
References: <20250912235515.367061-1-balbirs@nvidia.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=brT0Fr6Y;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Sat, 13 Sep 2025 09:55:15 +1000 Balbir Singh <balbirs@nvidia.com> wrote:

> commit c519c3c0a113 ("mm/kasan: avoid lazy MMU mode hazards") introduced
> the use of arch_enter_lazy_mmu_mode(), which results in the compiler
> complaining about "statement has no effect", when
> __HAVE_ARCH_LAZY_MMU_MODE is not defined in include/linux/pgtable.h
>=20
> The exact warning/error is:
>=20
> In file included from ./include/linux/kasan.h:37,
>                  from mm/kasan/shadow.c:14:
> mm/kasan/shadow.c: In function =E2=80=98kasan_populate_vmalloc_pte=E2=80=
=99:
> ./include/linux/pgtable.h:247:41: error: statement with no effect [-Werro=
r=3Dunused-value]
>   247 | #define arch_enter_lazy_mmu_mode()      (LAZY_MMU_DEFAULT)
>       |                                         ^
> mm/kasan/shadow.c:322:9: note: in expansion of macro =E2=80=98arch_enter_=
lazy_mmu_mode=E2=80=99
>   322 |         arch_enter_lazy_mmu_mode();
>       |         ^~~~~~~~~~~~~~~~~~~~~~~~
>=20
> Fix the issue by explicitly casting the use of the function to void,
> since the returned state is not forwarded/retained
>=20
> ...
>
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -319,7 +319,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, un=
signed long addr,
>  	}
>  	spin_unlock(&init_mm.page_table_lock);
> =20
> -	arch_enter_lazy_mmu_mode();
> +	(void)arch_enter_lazy_mmu_mode();
> =20
>  	return 0;
>  }
> @@ -494,7 +494,7 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, =
unsigned long addr,
>  	if (likely(!none))
>  		__free_page(pfn_to_page(pte_pfn(pte)));
> =20
> -	arch_enter_lazy_mmu_mode();
> +	(void)arch_enter_lazy_mmu_mode();
> =20
>  	return 0;

doh, I just figured out that my fix for your fix simply reverted your
fix!

I'll promote my cleanup into a hotfix:


From: Andrew Morton <akpm@linux-foundation.org>
Subject: include/linux/pgtable.h: convert arch_enter_lazy_mmu_mode() and fr=
iends to static inlines
Date: Sat Sep 13 05:03:39 PM PDT 2025

commit c519c3c0a113 ("mm/kasan: avoid lazy MMU mode hazards") introduced
the use of arch_enter_lazy_mmu_mode(), which results in the compiler
complaining about "statement has no effect", when
__HAVE_ARCH_LAZY_MMU_MODE is not defined in include/linux/pgtable.h

The exact warning/error is:

In file included from ./include/linux/kasan.h:37,
                 from mm/kasan/shadow.c:14:
mm/kasan/shadow.c: In function kasan_populate_vmalloc_pte:
./include/linux/pgtable.h:247:41: error: statement with no effect [-Werror=
=3Dunused-value]
  247 | #define arch_enter_lazy_mmu_mode()      (LAZY_MMU_DEFAULT)
      |                                         ^
mm/kasan/shadow.c:322:9: note: in expansion of macro arch_enter_lazy_mmu_mo=
de>   322 |         arch_enter_lazy_mmu_mode();
     |         ^~~~~~~~~~~~~~~~~~~~~~~~

switching these "functions" to static inlines fixes this up.

Fixes: c519c3c0a113 ("mm/kasan: avoid lazy MMU mode hazards")=20
Reported-by: Balbir Singh <balbirs@nvidia.com>
Closes: https://lkml.kernel.org/r/20250912235515.367061-1-balbirs@nvidia.co=
m
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 include/linux/pgtable.h |    6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

--- a/include/linux/pgtable.h~include-linux-pgtableh-convert-arch_enter_laz=
y_mmu_mode-and-friends-to-static-inlines
+++ a/include/linux/pgtable.h
@@ -232,9 +232,9 @@ static inline int pmd_dirty(pmd_t pmd)
  * and the mode cannot be used in interrupt context.
  */
 #ifndef __HAVE_ARCH_ENTER_LAZY_MMU_MODE
-#define arch_enter_lazy_mmu_mode()	do {} while (0)
-#define arch_leave_lazy_mmu_mode()	do {} while (0)
-#define arch_flush_lazy_mmu_mode()	do {} while (0)
+static inline void arch_enter_lazy_mmu_mode(void) {}
+static inline void arch_leave_lazy_mmu_mode(void) {}
+static inline void arch_flush_lazy_mmu_mode(void) {}
 #endif
=20
 #ifndef pte_batch_hint
_

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250925160736.a8c65952370d66d1544f9309%40linux-foundation.org.
