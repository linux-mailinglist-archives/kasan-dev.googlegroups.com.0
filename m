Return-Path: <kasan-dev+bncBAABBAXJRHEAMGQEP7BQHNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B719C1D270
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 21:09:40 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-592f3dedd1dsf338177e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 13:09:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761768580; cv=pass;
        d=google.com; s=arc-20240605;
        b=j2LqNy4C1U2ifk8EWanoRaRo56+rxKJqO5NosB0svufaMPNLWmY/4MCfY4rn9TxLR3
         XsoUZGhV6LACx1/DBzsSmb3KTyTlPIAlcTww5hYlMNsHG5TF8OJbEZmjikUDMgMeBhu/
         /ZxVV5wswwIkjOMnwyF2NSgDlC0MCD6NKS+1MN4K+xp6tUYW5o+Qyh4Uz34oqhHPVhax
         m1UyAtHTgRtLrvg8Tm2hV9rkUelyLfXHiE8GpyvwiwwHFd65ZOWqlLexu8dojsrqVzhN
         hPXxG0wuDkiv/zee9blEsz1ieJX4upS9Q//sajXFqq8jvJ1+jKUUVUlP8mDPgTn8REwU
         EbfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=5wLiClbvjo3vdFYsahObKZI93FXacWWHuL4rYkQl6a0=;
        fh=VJ2eUl+yGZQoj9dEc7iF81pXn+gol26LPAnvzQeBJS4=;
        b=ZoqtPPJmm989CLIUM96ehsIRb5JKYn4TDffTjKQRPPNWsvQrR+C1ophvqPdAit/sTz
         BoCb/cMtIC8mL/w3hFMGCvGsxvelzzafNtyDYJjGEjYj6R15CLEKAJHrhTOfhnBIjuBU
         magbzAHBi3gCK7l4qRSiHf9DsM0CED1kCtuWcI8ri5DkzOTrsFXqPD4wWBgUk8Eimpfw
         xwMIKIg8tWeFSbuYexf5fdz9SH+TmTp77Hzo2BJ70rEg62+5nUnzTvla//5FXyX2WWA7
         C3Fk+46Ezk5LnBl8ivMwTJzN4QM3kOwUzQrLwjEcYc4N3hk4yI+HM6CA0erbRXatAiLH
         miUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=GiO+NP1C;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761768580; x=1762373380; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=5wLiClbvjo3vdFYsahObKZI93FXacWWHuL4rYkQl6a0=;
        b=j5fncyjGhTexPiEJ1OQ9KCa1hAdlHtXDz/Ev8bWbUtVHzGdG9ezYITy5qA1NG/ZxyA
         plbmUqECPyk8qU3KrIUN00MrAc09JAwdpKjdjEtmXTSVtVuW+XQLGK1GAy2vfunZv63l
         nigZerOoRtTgLuE4aGDWGymHvx8xCAbXUpcyevtkIom5ROnsY2E78yPB4V4Liq6lCiDC
         kNOHFQ1Ghkn+ac8+kwW7j0V/XSDqQzBTuGDitUikgi+NM9ltCHmdUcxJpzVYxMjE4mcs
         pJvCeRMn5mcyRMxeEFBZGcHVQ/giZQ3wOrsJA/ysokY8Ti5Zi7ZA8sKLwEov8wktqCTF
         axtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761768580; x=1762373380;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5wLiClbvjo3vdFYsahObKZI93FXacWWHuL4rYkQl6a0=;
        b=O8JiY6UOkji3wyFZY2oFqMlF6ykiTvjSoKS4vt0ZUpzU2Gg55PaEMkCZsrpWX6IlM7
         gvVtRolGhiVpi5+KbuGHEAbG6CK5lHR6ASHdd9zNAbjpMQ76HPzrWS0UaJtDlcZjSD30
         czNXDlBnI833cpeTuIIMgGPgY9WBjy7bsd0LVrspse31SZ4I34OaMIUUjOpIvFHQQCok
         xslEuccTYhUHSpYNTxNWBa41XjEKbEKEuExxs6OuwlHRCZihQdzzJhU4cu8iaZVAZXva
         9UahiijL1OQP4hWrCyaKrzLjMSR0nBZ2B+6aUxF5yYdyHYq0T4UICQnJkKL9Eyf1rFcg
         1WWA==
X-Forwarded-Encrypted: i=2; AJvYcCV+QIMKlyiSuyRAcTYPrMIaPdetuvv7yqdyMg4m18SaTEL/yhVhTpb+v6+mJU+dRp5LJAjJ7w==@lfdr.de
X-Gm-Message-State: AOJu0Yzk0YvKV7k4+cE7K+D3KR8Jlx0qfEtan5Uo9p3o+h+f7mwTkj+e
	HrndmeEVQGcrPg/6IyFao9f7djJ6/Hz1e6pZ3rMZ7ZYsL2mRkTx8bC0m
X-Google-Smtp-Source: AGHT+IFOvvF/sJpCLrX7mms9DEXNwH3qmA5mpqse1NOsFUuJX95pisDRVhJThjOkgNHAr74pX/w9vA==
X-Received: by 2002:a05:6512:1291:b0:592:f7b7:2f6a with SMTP id 2adb3069b0e04-59416e94485mr216937e87.12.1761768579608;
        Wed, 29 Oct 2025 13:09:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bs1AFgFl13o17g8GfV0kwtILQ/tJ/RTzlOVyhtz5O7kw=="
Received: by 2002:a05:6512:401b:b0:564:4dfe:5a41 with SMTP id
 2adb3069b0e04-59417638273ls69783e87.1.-pod-prod-09-eu; Wed, 29 Oct 2025
 13:09:37 -0700 (PDT)
X-Received: by 2002:a05:6512:238a:b0:592:f5f9:f59f with SMTP id 2adb3069b0e04-59416eed147mr246276e87.31.1761768577086;
        Wed, 29 Oct 2025 13:09:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761768577; cv=none;
        d=google.com; s=arc-20240605;
        b=hedOL/9Qo5gpub9csNIFEN+yuARRgzG26J2ITP/TZl3y7x+fLpeTzON/5k1XqbfFIJ
         dIO0TB5YavnFQFI5ja7rPU9dsUQo+R5p78gQ1H1CW5PAi1kgU3ioIkyG/oOOqeVaKH+A
         Oe6Ud/ntGI2g7qsOhmTbMbq8nI4C+otBNIzDTlXoY6QO/exDij12eaMxTj4Vm8C82cY3
         P0/Ie5vlfWK+Ht4xhuCksdOIPQUsggCd7HfYziHekVBhjmOnUW3wGgxB98MoqUSKxVJF
         5ObqO8VKCfrkd6e1auq06YpVx0wRhAn7e7Z6bTWCHs96oj119ML23mcGV8TmL+GaUM2X
         eM3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=9kO+NK4R04JM70PmVsjA3ThrFoFrY2dEYZyEQtxD9Gc=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=lNiSRnG2ZoWYi/WMTTI3MPxfUMWJ3fyDNDpH1g+RUVDjp1Hz+TmRMigfjtft0b+REt
         trWvtT4sXILSloNiFveW4Ac35kNV5tNjf3pEdTKFKqGYYaeGJ034Ro6DvapDykGcfK5Z
         bZb6mH5pOaVX8r1UMorMhcO9RUjRoduRSVg8EAikqYMvcYu/RArODJfKCzVr1CpJ4Yh2
         ridAja48xuzRQhEAPIrm8C9roCE/7epFoT6oGjCk6XK1RVJ8bgTADsJUYXBB/zBMHYzr
         2Ndgg3d7fUMkwh7gst0jcOB1nTNav2+B9oQYcRlQv/DwlHD9kMmY2+wvWC1i2AofLQMY
         h55w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=GiO+NP1C;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4322.protonmail.ch (mail-4322.protonmail.ch. [185.70.43.22])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-593028a9f7asi281087e87.8.2025.10.29.13.09.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 13:09:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) client-ip=185.70.43.22;
Date: Wed, 29 Oct 2025 20:09:28 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 14/18] x86: Minimal SLAB alignment
Message-ID: <0ca5d46e292e5074c119c7c58e6ec9901fb0ed73.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: bb212e55891aa41be391c49c804782cab1b9ead2
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=GiO+NP1C;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

8 byte minimal SLAB alignment interferes with KASAN's granularity of 16
bytes. It causes a lot of out-of-bounds errors for unaligned 8 byte
allocations.

Compared to a kernel with KASAN disabled, the memory footprint increases
because all kmalloc-8 allocations now are realized as kmalloc-16, which
has twice the object size. But more meaningfully, when compared to a
kernel with generic KASAN enabled, there is no difference. Because of
redzones in generic KASAN, kmalloc-8' and kmalloc-16' object size is the
same (48 bytes). So changing the minimal SLAB alignment of the tag-based
mode doesn't have any negative impact when compared to the other
software KASAN mode.

Adjust x86 minimal SLAB alignment to match KASAN granularity size.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
---
Changelog v6:
- Add Andrey's Reviewed-by tag.

Changelog v4:
- Extend the patch message with some more context and impact
  information.

Changelog v3:
- Fix typo in patch message 4 -> 16.
- Change define location to arch/x86/include/asm/cache.c.

 arch/x86/include/asm/cache.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/arch/x86/include/asm/cache.h b/arch/x86/include/asm/cache.h
index 69404eae9983..3232583b5487 100644
--- a/arch/x86/include/asm/cache.h
+++ b/arch/x86/include/asm/cache.h
@@ -21,4 +21,8 @@
 #endif
 #endif
 
+#ifdef CONFIG_KASAN_SW_TAGS
+#define ARCH_SLAB_MINALIGN (1ULL << KASAN_SHADOW_SCALE_SHIFT)
+#endif
+
 #endif /* _ASM_X86_CACHE_H */
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0ca5d46e292e5074c119c7c58e6ec9901fb0ed73.1761763681.git.m.wieczorretman%40pm.me.
