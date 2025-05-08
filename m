Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIGS6HAAMGQE4FKBJNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id E9517AAF56B
	for <lists+kasan-dev@lfdr.de>; Thu,  8 May 2025 10:19:46 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-30c14d46b55sf777542a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 08 May 2025 01:19:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746692385; cv=pass;
        d=google.com; s=arc-20240605;
        b=K37rdWdW/EqI8rF6VzTCSxDpo5qyI0AaesePbW9koK+/WWUGbPQulGXrd08jaoWjEm
         962iQTAVerkAqLU+rymWaJK/9KSPNif4n90U8dTbNbdjnMPRUb1eYdBh22ssjtpn2odg
         2kcZ/RdZFvtMKN0Tm4COH/VwQ409MkwEkqhocGJvpcjMsWs6KbFwDkFnUL0/hUJv0CoL
         akVsNnJesLdSOVaPDjML445PwnOmOjadVXEJxyVeO/IIUuQEhpfQYzIK6EDEvVyxmKV4
         MkwjC8HMjXO9AGCiJfEeDcys1okknUUlhIPhoyAYcCtwje+wxUX26AgrFlpVnP8Y17tJ
         EKKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qLsCG3LKYUqBECS1IwscvKy9UYMBUkcWxBL3b/gHhl0=;
        fh=xtj44fsLBlKoSuvbgErrNVtuF/L9bSfyP7L24wrGFv0=;
        b=GH0Y6DnyUTasqQtgsE1XJeztFBAAn2svsENbh6bu1IaEbCJOaHmE9gewHZ8rEuHsMG
         qlrL8B4KhXDPlVOdcCvJiVi7t0lcuvnvxnA3QG3D68SrRQe04zmau2PtvnwNPKkRsQ4v
         lyQydpGnZV7QWIjkl5qZuOmmeg9S/wj7SfzXVDtDqec1kslnFRE72PszOghHSk497tmk
         PiO/BoY74PwT/DXcy3TVrL6h/gpdMTILC6sL2ZwBRK9E4TVXp1hLBqMDDxs9SDA86b1I
         /xh8tB+53MNXEWQEHIi0r3T1BXgqQTbvNhaoR6ESYchCVqtleeamumLZygbOVwacKE/d
         buNQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HmuYGjmX;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746692385; x=1747297185; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qLsCG3LKYUqBECS1IwscvKy9UYMBUkcWxBL3b/gHhl0=;
        b=L9p9f36+cPjGpD1doBtppWTyUjAt1uDl64pWDxysEQQ+SLr3l2yUJ6Bj5T5nlbEI9/
         rY2bcGDatB/t2lGbrz7O3smgRsPYM5d36tAUh527oAqPU4afersIC7UEpDkCOlGnqhZL
         xWL0p8u7Agq/TBqCeWdkR5M5/mqpOqi1o1tM5ltDvRainsYBFO0XYDvxJtk3AS4GI6nM
         okxa9I35w8wdsebAvwgQmDqUhNgdcXA2mf/qX3GMmFKcnDYnoJpaGylNlVYga/yapQwC
         6d1gRe98BQ8XWrtjIrfy4Ir09r3SYPDpQ9lnhnYtRerE3P+3F6vlsozd5LoEYez82xMr
         oWBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746692385; x=1747297185;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qLsCG3LKYUqBECS1IwscvKy9UYMBUkcWxBL3b/gHhl0=;
        b=uvJFdw/FtTp5/mOQKdvRu2UILNLM+WpIe7G42PpQCyaz+BJ3f6inIoYYP2haCeheGj
         y4sRq5htuSdKmzlkG3CTMstey5+ZMHNND8VpEoYqCEMkfqOrtxYxMc+vloQZdr5/cdgc
         shljqzatcgYhvzfP4AE/X+QBmuRaHAQdtfkxVGqfbQFN84Ul87B7rtIGdFwkYdaY7zIG
         rSZj7Ly7uC185vgJnejZIjX0G9ETs77UzxqG3vJXCwGX9rSssw6k94BE417xqzjiWHr7
         zVBEzG7GBJSXclhVAhG6srmdv04ptoYiPW7pCv5Swhfwc6n6dYOoI3AsHnw6kLHnMpCQ
         L6cg==
X-Forwarded-Encrypted: i=2; AJvYcCW+CmduP4L571Q5bQzXbMdzF9GwN7Y4kR3091OLIX0qnzOkHCfBGIGLfcHmferVMiAprJtdBg==@lfdr.de
X-Gm-Message-State: AOJu0Yxtj4PO5UtFIgfszR37AyRJ5pyofEhJ621Fg4OYoN5DoXhpTsce
	PFZIw8frrpbVRILKWz9pYChe4ZL44Htzny2WWog9ilwHEscg/SYU
X-Google-Smtp-Source: AGHT+IEYfaejR1EX0jJ46uL4RaxmL2w80lP+oWLK19t4t3WbqBQhfOGhH+cp3+PhlVK4f72wYI8Aig==
X-Received: by 2002:a17:90a:e7c4:b0:2ee:c291:765a with SMTP id 98e67ed59e1d1-30b32d34cbdmr3379856a91.8.1746692384878;
        Thu, 08 May 2025 01:19:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBH0yNWx3wO/5QKmahPykz8tWL2ZJYT1GQomFsShrF9mMg==
Received: by 2002:a17:90a:3944:b0:2ff:4f04:3973 with SMTP id
 98e67ed59e1d1-30ad8a213cals957450a91.2.-pod-prod-08-us; Thu, 08 May 2025
 01:19:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUUd2GxXZI7GjRssJMHO19qQ/HXlH9L1tBh35IMlk6f4Q6cBCNu7D4g7ZTNzc8xRmi+lB040q1LFDo=@googlegroups.com
X-Received: by 2002:a17:90b:3952:b0:2fe:b8ba:62de with SMTP id 98e67ed59e1d1-30b3a6d8161mr3426331a91.25.1746692383502;
        Thu, 08 May 2025 01:19:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746692383; cv=none;
        d=google.com; s=arc-20240605;
        b=ZqnzSPEeCBQ73e7bji0ZOxx+B9V1pkQ+NltMO/IhwrOqQe3m6yCIcjcG5IR2r/fTKF
         9tF00gkK6cRkYqPtxNlNc33lARx/L047uQ8Q0rDCMImJ17XpDSRyGihJNrhxkiEd4/rS
         BKfpY/4SNpgegLG5hzOey+H7xim5s4kC3CXwRNZlSuwVFtL2kZbbWUoU1cjHukijHjqS
         8+FPMHvQ+EwN4OxJSjveNYvSzxv4SRwPS+jOUiZoPj3BJ35KLZ3hbemJ1zIznuHE2W2a
         oWxAnV5tnUl1r9QyuVmBrmm6LuC28wMGKTDsh43Lh9mfwxmD4mDy+WLXlAt1hE3Jy64E
         y+1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=52VkJWUKu9po56zzc30MFEoaWWTa8U2EUDMrfHIwzGI=;
        fh=BTR59mietNVVu2HaHnOMQ/W+neUnSxGDvse1WDG2cOE=;
        b=bru0cYCgCyfvKZSOaU0J52ORRQx5UgsHbmD3eS1PnVV9vrHZ16RbuHC13b+ub3igqB
         0XkmyWj6UAfB1OD09dGiCKO9eKZ7uN7ZTP5njGSYfeio+N5peufCHW4aw0pnb2Q7qeM+
         XigIy84NFBX9sLRwxM/DbZq0Hwj76RjOQda3kqDqVgqCbo6A3EJIMCI0dtD9Gj1WR8eA
         QDgHrAK6cocAzovkoObwziVOGbS868eCAGrkexiKSSavF0TDDAu+xTvJzPgWMIfNDp7v
         OruaNh8ZZU82fkDq57L6hcwE23yVmF7etDQ9jU4OImUJDHxErPA1W3kn+xiBkZQJpZlx
         I7hw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HmuYGjmX;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x735.google.com (mail-qk1-x735.google.com. [2607:f8b0:4864:20::735])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30a8101963csi419845a91.0.2025.05.08.01.19.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 May 2025 01:19:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) client-ip=2607:f8b0:4864:20::735;
Received: by mail-qk1-x735.google.com with SMTP id af79cd13be357-7c922169051so43026785a.0
        for <kasan-dev@googlegroups.com>; Thu, 08 May 2025 01:19:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWuSYnOHozAwVHYVgiWtpSWZZRR/uuhR5GfDjb8JOI6FRtP5nwZgnkRgjnUeUYFdoheCPEVI6q7noI=@googlegroups.com
X-Gm-Gg: ASbGncspv0OWPm/8GC128Fl1pui/6FCqDyCROrEPj2rxIWNNIbzFZt0o03wFNMs/aUz
	Pr7D2BChouy94ejEzzlkpaI3gf7X3mVoO9nbFyurKIogwVzHw4RMthaJbi+1elmbz0ZsdanlN4V
	cPwEj92mFAvdj16bNZcb8l65HuLermcrBv47NuTPAh6GUKuqK6tT4W
X-Received: by 2002:a05:6214:4009:b0:6f5:473d:e52c with SMTP id
 6a1803df08f44-6f54c3a777fmr39535526d6.15.1746692382604; Thu, 08 May 2025
 01:19:42 -0700 (PDT)
MIME-Version: 1.0
References: <20250507160012.3311104-1-glider@google.com> <20250507160012.3311104-2-glider@google.com>
 <CANpmjNMUFmnVweY5zCkkszD39bhT3+eKk1-Qqc0LZTUdPN0x=Q@mail.gmail.com>
In-Reply-To: <CANpmjNMUFmnVweY5zCkkszD39bhT3+eKk1-Qqc0LZTUdPN0x=Q@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 8 May 2025 10:19:06 +0200
X-Gm-Features: ATxdqUF82TZNZdJ5NZ9DBr61uOEgkzx_derrNzCJpkoQ0suTxw1oBNH06TRw08o
Message-ID: <CAG_fn=VuaiTB11bJraxQjoVxp=0ML7Zoth1CYjczgUof3Rhqmw@mail.gmail.com>
Subject: Re: [PATCH 2/5] kmsan: fix usage of kmsan_enter_runtime() in kmsan_vmap_pages_range_noflush()
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, bvanassche@acm.org, kent.overstreet@linux.dev, 
	iii@linux.ibm.com, akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=HmuYGjmX;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, May 7, 2025 at 6:09=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
>
> On Wed, 7 May 2025 at 18:00, Alexander Potapenko <glider@google.com> wrot=
e:
> >
> > Only enter the runtime to call __vmap_pages_range_noflush(), so that er=
ror
> > handling does not skip kmsan_leave_runtime().
> >
> > This bug was spotted by CONFIG_WARN_CAPABILITY_ANALYSIS=3Dy
>
> Might be worth pointing out this is not yet upstream:
> https://lore.kernel.org/all/20250304092417.2873893-1-elver@google.com/

Thanks! I'll update the description (here and in the other patch) and
post v2 later today.

> Also, for future reference, feel free to dump the diff here that added
> the annotations that helped you find the missing kmsan*runtime()
> calls. I'm sure it'd be of interest to others. At one point we may
> upstream those annotations, too, but we'll need Capability Analysis
> upstream first (which is blocked by some Clang improvements that were
> requested).

The diff is below. I added a __no_matter() macro which isn't strictly
necessary (maybe we can remove it altogether), but I thought it'll be
more descriptive.

Author: Alexander Potapenko <glider@google.com>
Date:   Thu Apr 3 15:44:38 2025 +0200

    DO-NOT-SUBMIT: kmsan: enable capability analysis

    Add support for the new capability analysis framework to KMSAN.
    Use the KMSAN_RUNTIME capability token to ensure correctness of
    kmsan_enter_runtime()/kmsan_leave_runtime() usage.

    Cc: Marco Elver <elver@google.com>
    Cc: Bart Van Assche <bvanassche@acm.org>
    Cc: Kent Overstreet <kent.overstreet@linux.dev>
    Signed-off-by: Alexander Potapenko <glider@google.com>

diff --git a/mm/kmsan/Makefile b/mm/kmsan/Makefile
index 91cfdde642d16..94591d612384c 100644
--- a/mm/kmsan/Makefile
+++ b/mm/kmsan/Makefile
@@ -8,6 +8,7 @@ obj-y :=3D core.o instrumentation.o init.o hooks.o
report.o shadow.o
 KMSAN_SANITIZE :=3D n
 KCOV_INSTRUMENT :=3D n
 UBSAN_SANITIZE :=3D n
+CAPABILITY_ANALYSIS :=3D y

 # Disable instrumentation of KMSAN runtime with other tools.
 CC_FLAGS_KMSAN_RUNTIME :=3D -fno-stack-protector
diff --git a/mm/kmsan/kmsan.h b/mm/kmsan/kmsan.h
index bc3d1810f352c..441c9dd39fe2a 100644
--- a/mm/kmsan/kmsan.h
+++ b/mm/kmsan/kmsan.h
@@ -35,6 +35,9 @@
 #define KMSAN_META_SHADOW (false)
 #define KMSAN_META_ORIGIN (true)

+token_capability(KMSAN_RUNTIME);
+#define __no_matter(X)
+
 /*
  * A pair of metadata pointers to be returned by the instrumentation funct=
ions.
  */
@@ -74,7 +77,7 @@ void kmsan_print_origin(depot_stack_handle_t origin);
  */
 void kmsan_report(depot_stack_handle_t origin, void *address, int size,
                  int off_first, int off_last, const void __user *user_addr=
,
-                 enum kmsan_bug_reason reason);
+                 enum kmsan_bug_reason reason) __must_not_hold(KMSAN_RUNTI=
ME);

 DECLARE_PER_CPU(struct kmsan_ctx, kmsan_percpu_ctx);

@@ -107,6 +110,7 @@ static __always_inline bool kmsan_in_runtime(void)
 }

 static __always_inline void kmsan_enter_runtime(void)
+       __acquires(KMSAN_RUNTIME) __no_capability_analysis
 {
        struct kmsan_ctx *ctx;

@@ -115,6 +119,7 @@ static __always_inline void kmsan_enter_runtime(void)
 }

 static __always_inline void kmsan_leave_runtime(void)
+       __releases(KMSAN_RUNTIME) __no_capability_analysis
 {
        struct kmsan_ctx *ctx =3D kmsan_get_context();

@@ -122,7 +127,8 @@ static __always_inline void kmsan_leave_runtime(void)
 }

 depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
-                                                unsigned int extra_bits);
+                                                unsigned int extra_bits)
+       __must_hold(KMSAN_RUNTIME);

 /*
  * Pack and unpack the origin chain depth and UAF flag to/from the extra b=
its
@@ -151,19 +157,26 @@ static __always_inline unsigned int
kmsan_depth_from_eb(unsigned int extra_bits)
  * kmsan_internal_ functions are supposed to be very simple and not requir=
e the
  * kmsan_in_runtime() checks.
  */
-void kmsan_internal_memmove_metadata(void *dst, void *src, size_t n);
+void kmsan_internal_memmove_metadata(void *dst, void *src, size_t n)
+       __must_hold(KMSAN_RUNTIME);
 void kmsan_internal_poison_memory(void *address, size_t size, gfp_t flags,
-                                 unsigned int poison_flags);
-void kmsan_internal_unpoison_memory(void *address, size_t size, bool check=
ed);
+                                 unsigned int poison_flags)
+       __must_hold(KMSAN_RUNTIME);
+void kmsan_internal_unpoison_memory(void *address, size_t size, bool check=
ed)
+       __no_matter(KMSAN_RUNTIME);
+
 void kmsan_internal_set_shadow_origin(void *address, size_t size, int b,
-                                     u32 origin, bool checked);
-depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id);
+                                     u32 origin, bool checked)
+       __no_matter(KMSAN_RUNTIME);
+depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
+       __must_hold(KMSAN_RUNTIME);

 void kmsan_internal_task_create(struct task_struct *task);

 bool kmsan_metadata_is_contiguous(void *addr, size_t size);
 void kmsan_internal_check_memory(void *addr, size_t size,
-                                const void __user *user_addr, int reason);
+                                const void __user *user_addr, int reason)
+       __must_not_hold(KMSAN_RUNTIME);

 struct page *kmsan_vmalloc_to_page_or_null(void *vaddr);
 void kmsan_setup_meta(struct page *page, struct page *shadow,

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DVuaiTB11bJraxQjoVxp%3D0ML7Zoth1CYjczgUof3Rhqmw%40mail.gmail.com.
