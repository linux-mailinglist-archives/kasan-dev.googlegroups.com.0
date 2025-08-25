Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFUKWLCQMGQEWPG6EJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id E4618B34631
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 17:45:27 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-61c35ffef1dsf1717666a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 08:45:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756136727; cv=pass;
        d=google.com; s=arc-20240605;
        b=YOTOAFpncfYPjDzzkMAc1G3sc0NUBEbzoY0J11oWIwnaue/AgYYmy0S1JhBwPlUkTx
         rIseyoyNBWVYSnSJ1xbmv4MmsB+TBJycFliTbs77lDws+E94sXrUPuxZ0iOgSEa0rK9Z
         HydZzljXTvoRY9VEDwfR8XG/gN/nAYH9sJ5opFQtVFe3xkyKU6Sv/dgbV6oAIHhB5Ybn
         wS8AhwNxLiX4z2q7OL7NodZdfkrnXAfPSPzyoyRv4K1IEigdjGocfcyfW5aVwnszU9kE
         /3iM61qQeyqvGYwOOL4Jr8sPxD1B1ijiDEZ62Ki7P68WtGWhKwS9OI440gFa26QUTbQ+
         Yd7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=O3X7p6g9NFdmudlKCrCPexy9d5bXyPA8Kl8Xd0NCsgI=;
        fh=ROErFAWLIbl4mFzO/hMYT5S4D04emror45A1QHIjpMY=;
        b=Xqw30dOoVixXCMWSg+le2/1YwwvWUsZ74WT7L5fAK4oT30nfUdl8DXtOQGw4pbfwnO
         RBTmEeQEPHYo9eWVIHNep1gE7upSVtlNyu65bFj6dIxF23U02fNCVWsxgGKgNiUEEhOA
         a+nNSbfThS8VwCs3MzunrDphwfRDADSK0S8AIm//xuwe+7ZaUahd8bDaFTQRQ5FHE9YK
         77WZUsO7KWcRNbj8RrrMXca7nuxHhEe83Lwx2Yf1rZI0NLXmFDAAIFk5RD9y23Mvcz7X
         qYsnx5I6JufTRJDQAXLfkW0wtP35bTcJOKqf3SeXcU4wHRTKy1jlvvE58S9+f2oXPqpx
         sVNg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=v4ZnYEZM;
       spf=pass (google.com: domain of 3eywsaaukcro4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3EYWsaAUKCRo4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756136727; x=1756741527; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=O3X7p6g9NFdmudlKCrCPexy9d5bXyPA8Kl8Xd0NCsgI=;
        b=qHIvw1+LpnpVAJ+lCFiWzAtRa9SlVvPJ9k+aXjV1IigTqsh06/6y5Lbat1HOAKF2xk
         1aQUPjdfRlVP+D15OHSxgS/N6aG+qs1Hh6MQ27WLHpgBPq4IV0tov8aSxRNGsFrwHBHo
         g84RbRl5lVNBvhduVZzyKEKLwLLbkiS6kriNwd+ZOQ92ej5ly7LK8occP5cDDD9GSebj
         kalCZ19UrLdBPgjrbrxFrE/sgCB5ufM2qhvrTKnkANge6jeE7GYAV12SCuhojcLtXtas
         OG/AHxExVG4P0WFxBkycUDNotiV4blwFlpkDmr0V/zbpqScoyDxVXOzSGre/Yb/aabIn
         W69A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756136727; x=1756741527;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=O3X7p6g9NFdmudlKCrCPexy9d5bXyPA8Kl8Xd0NCsgI=;
        b=NM7pxE5Un4n56uz9II6oFvKpaJI3YyF7nAhXUKGmLhcu9+ZQvqXSlMl9Gecra8hRYG
         YRqCz988V3O3wBTp9zm4L+3tXDAdtDVpeP1DT1b61rb05JH2Y1Z3uv3B0pXX8B4QCm97
         ALgP8VwSjsYutFnHjfctsa50tD4t9SodQ0Ej8itkB0ytvwdRk369mCxUj5A6QlxBPPKq
         NgXWfdrg3FgQkfUoVDAsafcug6a3LDfH2eFsJFNXV9f0qHlrf8dWL3NcmdSRVVl+1bDW
         kC//2D064+5JNEU+cgcPOXwt3MGElQh+5uPeR3zgNQnxWxOWHSlxP1/0xY83xEl/0zzS
         R3ig==
X-Forwarded-Encrypted: i=2; AJvYcCU1DGyy/ueYFtgyv84Ipye3KRvjkZdawqD8AIYTU1gFgIT1cgjiyyCM6ymiyaebes5rOK450g==@lfdr.de
X-Gm-Message-State: AOJu0YxZcuV2sCqzEQ2A4C4KdrXqJKw1U1A4Ma+ukPW4fmCwdhK+f2MS
	E1exTNFs8VnbK1W/jaOrIKxSaqtgObJ8vZ52SpTAOHFRyebCBvQW6Q9P
X-Google-Smtp-Source: AGHT+IEaaLTVA3wVe6P7ab/zKm8QMI+76uMCmbJ8ys1YbAsY1xaUrgKrtBCkq+kRHHU+oZ3eJEdNSQ==
X-Received: by 2002:a05:6402:4310:b0:61c:6fe4:445e with SMTP id 4fb4d7f45d1cf-61c8d0c8ef6mr53028a12.10.1756136727176;
        Mon, 25 Aug 2025 08:45:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeJsJIZDhLDBP8LHeA5NgH5HsSq5MC7+/7w0v+AwgU76Q==
Received: by 2002:aa7:d492:0:b0:61c:21f1:52b9 with SMTP id 4fb4d7f45d1cf-61c21f15640ls1127245a12.1.-pod-prod-00-eu-canary;
 Mon, 25 Aug 2025 08:45:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW3H4RoQxQdGWKNVFFioNETImShSIkWJwN6955YGom/4PKgrX/FT0HepL/dFRsQXliVCAPnGxzvk1A=@googlegroups.com
X-Received: by 2002:a17:906:794a:b0:afc:aac3:6d2 with SMTP id a640c23a62f3a-afe9cb66a21mr8092766b.2.1756136722048;
        Mon, 25 Aug 2025 08:45:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756136722; cv=none;
        d=google.com; s=arc-20240605;
        b=DfiMXSkLd2P5B8xdC35faFyrdo9w51DMcFab+r3Z8UrhnAGBvn0bPMWNY3SVAdOQ+X
         qNQ7T3JZxkr627pKk84PgY64Nd7t0egAOYFOnE9S6338rNRGWv4ngYg4Zrngh9nwvRwm
         HJIDG5VKpROsYCP7VSdreuO+/i57pj7t3W7OuL4AUs+NkykllTwYt5Y7t3575H9QYrWu
         YceA1+GfZeRgHwJducZeAkHU72cjrQ+a9eFFuljIa0NaVsanFdADGPZcLluC40lbeiKI
         psYpyZqOwwxpLpD3I117urII4a8TfoMqfpoukhzcMBiP0lZZ4XQNY0Bg3bM4JyxjNPlN
         uh6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=xe3ZI6MnUgwFYgdlik+eGR2/g7UExZaNNrV7DLC0Hwk=;
        fh=P0mBkZYxkGlhvDgYfMBMiolzCzKgjE0MvttHynC6c34=;
        b=ffYlf2NVuRnyrCkg/meNL34/drlsUPm8OG/F/zdO65Qd1CB9cfo6jJG/HcUOfFm1Ov
         tOZC9Frg0v9OJnwVYXZEkWiRI3ycGSORO/RlYU9iRduzPDqsCP3bNu4otuLlZLHoG3N8
         N7bvl+p4zLud3bnLRQxrAjQX6mz4OuDl6LK/rVK94JtlJREIZWn/rmZ24O4LTZcCV52i
         MIveiSNoEzsZlu9TuybgiplpH/KOto1eipuK0Ddy2suAvF9F4inFDZ8jqZuXhhqJ1lSf
         Txry27NNHagDw9hUufuD2AD6rHfxPCJ7kWQpY+IsBeRn4UNenKOLyzb41dhki+B6SIin
         ek6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=v4ZnYEZM;
       spf=pass (google.com: domain of 3eywsaaukcro4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3EYWsaAUKCRo4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-afe4901fbd4si13776666b.2.2025.08.25.08.45.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Aug 2025 08:45:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3eywsaaukcro4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-61c6d735f2aso859475a12.0
        for <kasan-dev@googlegroups.com>; Mon, 25 Aug 2025 08:45:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVlhv9U93vRTVbAm+z5hm4WVhMEIcXt+xOuHpc2Bzw9sxGpl2Ewj8csNEskDOxfGzr+xw02t9Z/VGY=@googlegroups.com
X-Received: from edaa12.prod.google.com ([2002:a05:6402:24cc:b0:61c:5f40:a3ff])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:21c8:b0:61b:fd1c:a2d6
 with SMTP id 4fb4d7f45d1cf-61c1b49e8f3mr11045108a12.15.1756136721629; Mon, 25
 Aug 2025 08:45:21 -0700 (PDT)
Date: Mon, 25 Aug 2025 17:44:40 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.51.0.rc2.233.g662b1ed5c5-goog
Message-ID: <20250825154505.1558444-1-elver@google.com>
Subject: [PATCH RFC] slab: support for compiler-assisted type-based slab cache partitioning
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, David Hildenbrand <david@redhat.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Florent Revest <revest@google.com>, GONG Ruiqi <gongruiqi@huaweicloud.com>, 
	Harry Yoo <harry.yoo@oracle.com>, Jann Horn <jannh@google.com>, Kees Cook <kees@kernel.org>, 
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, Matteo Rizzo <matteorizzo@google.com>, 
	Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Suren Baghdasaryan <surenb@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, linux-hardening@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=v4ZnYEZM;       spf=pass
 (google.com: domain of 3eywsaaukcro4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3EYWsaAUKCRo4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

[ Beware, this an early RFC for an in-development Clang feature, and
  requires the following Clang/LLVM development tree:
   https://github.com/melver/llvm-project/tree/alloc-token
  The corresponding LLVM RFC and discussion can be found here:
   https://discourse.llvm.org/t/rfc-a-framework-for-allocator-partitioning-hints/87434 ]

Rework the general infrastructure around RANDOM_KMALLOC_CACHES into more
flexible PARTITION_KMALLOC_CACHES, with the former being a partitioning
mode of the latter.

Introduce a new mode, TYPED_KMALLOC_CACHES, which leverages Clang's
"allocation tokens" via __builtin_alloc_token_infer [1].

This mechanism allows the compiler to pass a token ID derived from the
allocation's type to the allocator. The compiler performs best-effort
type inference, and recognizes idioms such as kmalloc(sizeof(T), ...).
Unlike RANDOM_KMALLOC_CACHES, this mode deterministically assigns a slab
cache to an allocation of type T, regardless of allocation site.

Clang's default token ID calculation is described as [1]:

   TypeHashPointerSplit: This mode assigns a token ID based on the hash
   of the allocated type's name, where the top half ID-space is reserved
   for types that contain pointers and the bottom half for types that do
   not contain pointers.

Separating pointer-containing objects from pointerless objects and data
allocations can help mitigate certain classes of memory corruption
exploits [2]: attackers who gains a buffer overflow on a primitive
buffer cannot use it to directly corrupt pointers or other critical
metadata in an object residing in a different, isolated heap region.

It is important to note that heap isolation strategies offer a
best-effort approach, and do not provide a 100% security guarantee,
albeit achievable at relatively low performance cost. Note that this
also does not prevent cross-cache attacks, and SLAB_VIRTUAL [3] should
be used as a complementary mitigation.

With all that, my kernel (x86 defconfig) shows me a histogram of slab
cache object distribution per /proc/slabinfo (after boot):

  <slab cache>      <objs> <hist>
  kmalloc-part-15     619  ++++++
  kmalloc-part-14    1412  ++++++++++++++
  kmalloc-part-13    1063  ++++++++++
  kmalloc-part-12    1745  +++++++++++++++++
  kmalloc-part-11     891  ++++++++
  kmalloc-part-10     610  ++++++
  kmalloc-part-09     792  +++++++
  kmalloc-part-08    3054  ++++++++++++++++++++++++++++++
  kmalloc-part-07     245  ++
  kmalloc-part-06     182  +
  kmalloc-part-05     122  +
  kmalloc-part-04     295  ++
  kmalloc-part-03     241  ++
  kmalloc-part-02     107  +
  kmalloc-part-01     124  +
  kmalloc            6231  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

The above /proc/slabinfo snapshot shows me there are 7547 allocated
objects (slabs 00 - 07) that the compiler claims contain no pointers or
it was unable to infer the type of, and 10186 objects that contain
pointers (slabs 08 - 15). On a whole, this looks relatively sane.

Additionally, when I compile my kernel with -Rpass=alloc-token, which
provides diagnostics where (after dead-code elimination) type inference
failed, I see 966 allocation sites where the compiler failed to identify
a type. Some initial review confirms these are mostly variable sized
buffers, but also include structs with trailing flexible length arrays
(the latter could be recognized by the compiler by teaching it to look
more deeply into complex expressions such as those generated by
struct_size).

Link: https://github.com/melver/llvm-project/blob/alloc-token/clang/docs/AllocToken.rst [1]
Link: https://blog.dfsec.com/ios/2025/05/30/blasting-past-ios-18/ [2]
Link: https://lwn.net/Articles/944647/ [3]
Signed-off-by: Marco Elver <elver@google.com>
---
 Makefile                        |  5 ++
 include/linux/percpu.h          |  2 +-
 include/linux/slab.h            | 88 ++++++++++++++++++++-------------
 kernel/configs/hardening.config |  2 +-
 mm/Kconfig                      | 43 ++++++++++++----
 mm/kfence/kfence_test.c         |  4 +-
 mm/slab.h                       |  4 +-
 mm/slab_common.c                | 48 +++++++++---------
 mm/slub.c                       | 20 ++++----
 9 files changed, 131 insertions(+), 85 deletions(-)

diff --git a/Makefile b/Makefile
index d1adb78c3596..cc761267fc75 100644
--- a/Makefile
+++ b/Makefile
@@ -936,6 +936,11 @@ KBUILD_CFLAGS	+= $(CC_AUTO_VAR_INIT_ZERO_ENABLER)
 endif
 endif
 
+ifdef CONFIG_TYPED_KMALLOC_CACHES
+# PARTITION_KMALLOC_CACHES_NR + 1
+KBUILD_CFLAGS	+= -falloc-token-max=16
+endif
+
 # Explicitly clear padding bits during variable initialization
 KBUILD_CFLAGS += $(call cc-option,-fzero-init-padding-bits=all)
 
diff --git a/include/linux/percpu.h b/include/linux/percpu.h
index 85bf8dd9f087..271b41be314d 100644
--- a/include/linux/percpu.h
+++ b/include/linux/percpu.h
@@ -36,7 +36,7 @@
 #define PCPU_BITMAP_BLOCK_BITS		(PCPU_BITMAP_BLOCK_SIZE >>	\
 					 PCPU_MIN_ALLOC_SHIFT)
 
-#ifdef CONFIG_RANDOM_KMALLOC_CACHES
+#ifdef CONFIG_PARTITION_KMALLOC_CACHES
 # if defined(CONFIG_LOCKDEP) && !defined(CONFIG_PAGE_SIZE_4KB)
 # define PERCPU_DYNAMIC_SIZE_SHIFT      13
 # else
diff --git a/include/linux/slab.h b/include/linux/slab.h
index d5a8ab98035c..4ace54744b54 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -583,10 +583,10 @@ static inline unsigned int arch_slab_minalign(void)
 #define SLAB_OBJ_MIN_SIZE      (KMALLOC_MIN_SIZE < 16 ? \
                                (KMALLOC_MIN_SIZE) : 16)
 
-#ifdef CONFIG_RANDOM_KMALLOC_CACHES
-#define RANDOM_KMALLOC_CACHES_NR	15 // # of cache copies
+#ifdef CONFIG_PARTITION_KMALLOC_CACHES
+#define PARTITION_KMALLOC_CACHES_NR	15 // # of cache copies
 #else
-#define RANDOM_KMALLOC_CACHES_NR	0
+#define PARTITION_KMALLOC_CACHES_NR	0
 #endif
 
 /*
@@ -605,8 +605,8 @@ enum kmalloc_cache_type {
 #ifndef CONFIG_MEMCG
 	KMALLOC_CGROUP = KMALLOC_NORMAL,
 #endif
-	KMALLOC_RANDOM_START = KMALLOC_NORMAL,
-	KMALLOC_RANDOM_END = KMALLOC_RANDOM_START + RANDOM_KMALLOC_CACHES_NR,
+	KMALLOC_PARTITION_START = KMALLOC_NORMAL,
+	KMALLOC_PARTITION_END = KMALLOC_PARTITION_START + PARTITION_KMALLOC_CACHES_NR,
 #ifdef CONFIG_SLUB_TINY
 	KMALLOC_RECLAIM = KMALLOC_NORMAL,
 #else
@@ -633,9 +633,20 @@ extern kmem_buckets kmalloc_caches[NR_KMALLOC_TYPES];
 	(IS_ENABLED(CONFIG_ZONE_DMA)   ? __GFP_DMA : 0) |	\
 	(IS_ENABLED(CONFIG_MEMCG) ? __GFP_ACCOUNT : 0))
 
+#ifdef CONFIG_RANDOM_KMALLOC_CACHES
 extern unsigned long random_kmalloc_seed;
+typedef struct { unsigned long ip; } kmalloc_token_t;
+#define __kmalloc_token(...) ((kmalloc_token_t) { .ip = _RET_IP_ })
+#elif defined(CONFIG_TYPED_KMALLOC_CACHES)
+typedef struct { unsigned long v; } kmalloc_token_t;
+#define __kmalloc_token(...) ((kmalloc_token_t){ .v = __builtin_alloc_token_infer(__VA_ARGS__) })
+#else
+/* no-op */
+typedef struct {} kmalloc_token_t;
+#define __kmalloc_token(...) ((kmalloc_token_t){})
+#endif
 
-static __always_inline enum kmalloc_cache_type kmalloc_type(gfp_t flags, unsigned long caller)
+static __always_inline enum kmalloc_cache_type kmalloc_type(gfp_t flags, kmalloc_token_t token)
 {
 	/*
 	 * The most common case is KMALLOC_NORMAL, so test for it
@@ -643,9 +654,11 @@ static __always_inline enum kmalloc_cache_type kmalloc_type(gfp_t flags, unsigne
 	 */
 	if (likely((flags & KMALLOC_NOT_NORMAL_BITS) == 0))
 #ifdef CONFIG_RANDOM_KMALLOC_CACHES
-		/* RANDOM_KMALLOC_CACHES_NR (=15) copies + the KMALLOC_NORMAL */
-		return KMALLOC_RANDOM_START + hash_64(caller ^ random_kmalloc_seed,
-						      ilog2(RANDOM_KMALLOC_CACHES_NR + 1));
+		/* PARTITION_KMALLOC_CACHES_NR (=15) copies + the KMALLOC_NORMAL */
+		return KMALLOC_PARTITION_START + hash_64(token.ip ^ random_kmalloc_seed,
+							 ilog2(PARTITION_KMALLOC_CACHES_NR + 1));
+#elif defined(CONFIG_TYPED_KMALLOC_CACHES)
+		return KMALLOC_PARTITION_START + token.v;
 #else
 		return KMALLOC_NORMAL;
 #endif
@@ -819,10 +832,10 @@ void *kmem_cache_alloc_node_noprof(struct kmem_cache *s, gfp_t flags,
  * with the exception of kunit tests
  */
 
-void *__kmalloc_noprof(size_t size, gfp_t flags)
+void *__kmalloc_noprof(size_t size, gfp_t flags, kmalloc_token_t token)
 				__assume_kmalloc_alignment __alloc_size(1);
 
-void *__kmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node)
+void *__kmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node, kmalloc_token_t token)
 				__assume_kmalloc_alignment __alloc_size(1);
 
 void *__kmalloc_cache_noprof(struct kmem_cache *s, gfp_t flags, size_t size)
@@ -893,7 +906,7 @@ void *__kmalloc_large_node_noprof(size_t size, gfp_t flags, int node)
  *	Try really hard to succeed the allocation but fail
  *	eventually.
  */
-static __always_inline __alloc_size(1) void *kmalloc_noprof(size_t size, gfp_t flags)
+static __always_inline __alloc_size(1) void *_kmalloc_noprof(size_t size, gfp_t flags, kmalloc_token_t token)
 {
 	if (__builtin_constant_p(size) && size) {
 		unsigned int index;
@@ -903,20 +916,21 @@ static __always_inline __alloc_size(1) void *kmalloc_noprof(size_t size, gfp_t f
 
 		index = kmalloc_index(size);
 		return __kmalloc_cache_noprof(
-				kmalloc_caches[kmalloc_type(flags, _RET_IP_)][index],
+				kmalloc_caches[kmalloc_type(flags, token)][index],
 				flags, size);
 	}
-	return __kmalloc_noprof(size, flags);
+	return __kmalloc_noprof(size, flags, token);
 }
+#define kmalloc_noprof(...)			_kmalloc_noprof(__VA_ARGS__, __kmalloc_token(__VA_ARGS__))
 #define kmalloc(...)				alloc_hooks(kmalloc_noprof(__VA_ARGS__))
 
 #define kmem_buckets_alloc(_b, _size, _flags)	\
-	alloc_hooks(__kmalloc_node_noprof(PASS_BUCKET_PARAMS(_size, _b), _flags, NUMA_NO_NODE))
+	alloc_hooks(__kmalloc_node_noprof(PASS_BUCKET_PARAMS(_size, _b), _flags, NUMA_NO_NODE, __kmalloc_token(_size)))
 
 #define kmem_buckets_alloc_track_caller(_b, _size, _flags)	\
-	alloc_hooks(__kmalloc_node_track_caller_noprof(PASS_BUCKET_PARAMS(_size, _b), _flags, NUMA_NO_NODE, _RET_IP_))
+	alloc_hooks(__kmalloc_node_track_caller_noprof(PASS_BUCKET_PARAMS(_size, _b), _flags, NUMA_NO_NODE, _RET_IP_, __kmalloc_token(_size)))
 
-static __always_inline __alloc_size(1) void *kmalloc_node_noprof(size_t size, gfp_t flags, int node)
+static __always_inline __alloc_size(1) void *_kmalloc_node_noprof(size_t size, gfp_t flags, int node, kmalloc_token_t token)
 {
 	if (__builtin_constant_p(size) && size) {
 		unsigned int index;
@@ -926,11 +940,12 @@ static __always_inline __alloc_size(1) void *kmalloc_node_noprof(size_t size, gf
 
 		index = kmalloc_index(size);
 		return __kmalloc_cache_node_noprof(
-				kmalloc_caches[kmalloc_type(flags, _RET_IP_)][index],
+				kmalloc_caches[kmalloc_type(flags, token)][index],
 				flags, node, size);
 	}
-	return __kmalloc_node_noprof(PASS_BUCKET_PARAMS(size, NULL), flags, node);
+	return __kmalloc_node_noprof(PASS_BUCKET_PARAMS(size, NULL), flags, node, token);
 }
+#define kmalloc_node_noprof(...)		_kmalloc_node_noprof(__VA_ARGS__, __kmalloc_token(__VA_ARGS__))
 #define kmalloc_node(...)			alloc_hooks(kmalloc_node_noprof(__VA_ARGS__))
 
 /**
@@ -939,14 +954,15 @@ static __always_inline __alloc_size(1) void *kmalloc_node_noprof(size_t size, gf
  * @size: element size.
  * @flags: the type of memory to allocate (see kmalloc).
  */
-static inline __alloc_size(1, 2) void *kmalloc_array_noprof(size_t n, size_t size, gfp_t flags)
+static inline __alloc_size(1, 2) void *_kmalloc_array_noprof(size_t n, size_t size, gfp_t flags, kmalloc_token_t token)
 {
 	size_t bytes;
 
 	if (unlikely(check_mul_overflow(n, size, &bytes)))
 		return NULL;
-	return kmalloc_noprof(bytes, flags);
+	return _kmalloc_noprof(bytes, flags, token);
 }
+#define kmalloc_array_noprof(...)		_kmalloc_array_noprof(__VA_ARGS__, __kmalloc_token(__VA_ARGS__))
 #define kmalloc_array(...)			alloc_hooks(kmalloc_array_noprof(__VA_ARGS__))
 
 /**
@@ -989,9 +1005,9 @@ static inline __realloc_size(2, 3) void * __must_check krealloc_array_noprof(voi
 #define kcalloc(n, size, flags)		kmalloc_array(n, size, (flags) | __GFP_ZERO)
 
 void *__kmalloc_node_track_caller_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node,
-					 unsigned long caller) __alloc_size(1);
+					 unsigned long caller, kmalloc_token_t token) __alloc_size(1);
 #define kmalloc_node_track_caller_noprof(size, flags, node, caller) \
-	__kmalloc_node_track_caller_noprof(PASS_BUCKET_PARAMS(size, NULL), flags, node, caller)
+	__kmalloc_node_track_caller_noprof(PASS_BUCKET_PARAMS(size, NULL), flags, node, caller, __kmalloc_token(size))
 #define kmalloc_node_track_caller(...)		\
 	alloc_hooks(kmalloc_node_track_caller_noprof(__VA_ARGS__, _RET_IP_))
 
@@ -1008,17 +1024,18 @@ void *__kmalloc_node_track_caller_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flag
 #define kmalloc_track_caller_noprof(...)	\
 		kmalloc_node_track_caller_noprof(__VA_ARGS__, NUMA_NO_NODE, _RET_IP_)
 
-static inline __alloc_size(1, 2) void *kmalloc_array_node_noprof(size_t n, size_t size, gfp_t flags,
-							  int node)
+static inline __alloc_size(1, 2) void *_kmalloc_array_node_noprof(size_t n, size_t size, gfp_t flags,
+								  int node, kmalloc_token_t token)
 {
 	size_t bytes;
 
 	if (unlikely(check_mul_overflow(n, size, &bytes)))
 		return NULL;
 	if (__builtin_constant_p(n) && __builtin_constant_p(size))
-		return kmalloc_node_noprof(bytes, flags, node);
-	return __kmalloc_node_noprof(PASS_BUCKET_PARAMS(bytes, NULL), flags, node);
+		return _kmalloc_node_noprof(bytes, flags, node, token);
+	return __kmalloc_node_noprof(PASS_BUCKET_PARAMS(bytes, NULL), flags, node, token);
 }
+#define kmalloc_array_node_noprof(...)		_kmalloc_array_node_noprof(__VA_ARGS__, __kmalloc_token(__VA_ARGS__))
 #define kmalloc_array_node(...)			alloc_hooks(kmalloc_array_node_noprof(__VA_ARGS__))
 
 #define kcalloc_node(_n, _size, _flags, _node)	\
@@ -1034,16 +1051,17 @@ static inline __alloc_size(1, 2) void *kmalloc_array_node_noprof(size_t n, size_
  * @size: how many bytes of memory are required.
  * @flags: the type of memory to allocate (see kmalloc).
  */
-static inline __alloc_size(1) void *kzalloc_noprof(size_t size, gfp_t flags)
+static inline __alloc_size(1) void *_kzalloc_noprof(size_t size, gfp_t flags, kmalloc_token_t token)
 {
-	return kmalloc_noprof(size, flags | __GFP_ZERO);
+	return _kmalloc_noprof(size, flags | __GFP_ZERO, token);
 }
+#define kzalloc_noprof(...)			_kzalloc_noprof(__VA_ARGS__, __kmalloc_token(__VA_ARGS__))
 #define kzalloc(...)				alloc_hooks(kzalloc_noprof(__VA_ARGS__))
 #define kzalloc_node(_size, _flags, _node)	kmalloc_node(_size, (_flags)|__GFP_ZERO, _node)
 
-void *__kvmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node) __alloc_size(1);
+void *__kvmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node, kmalloc_token_t token) __alloc_size(1);
 #define kvmalloc_node_noprof(size, flags, node)	\
-	__kvmalloc_node_noprof(PASS_BUCKET_PARAMS(size, NULL), flags, node)
+	__kvmalloc_node_noprof(PASS_BUCKET_PARAMS(size, NULL), flags, node, __kmalloc_token(size))
 #define kvmalloc_node(...)			alloc_hooks(kvmalloc_node_noprof(__VA_ARGS__))
 
 #define kvmalloc(_size, _flags)			kvmalloc_node(_size, _flags, NUMA_NO_NODE)
@@ -1052,19 +1070,19 @@ void *__kvmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node)
 
 #define kvzalloc_node(_size, _flags, _node)	kvmalloc_node(_size, (_flags)|__GFP_ZERO, _node)
 #define kmem_buckets_valloc(_b, _size, _flags)	\
-	alloc_hooks(__kvmalloc_node_noprof(PASS_BUCKET_PARAMS(_size, _b), _flags, NUMA_NO_NODE))
+	alloc_hooks(__kvmalloc_node_noprof(PASS_BUCKET_PARAMS(_size, _b), _flags, NUMA_NO_NODE, __kmalloc_token(_size)))
 
 static inline __alloc_size(1, 2) void *
-kvmalloc_array_node_noprof(size_t n, size_t size, gfp_t flags, int node)
+_kvmalloc_array_node_noprof(size_t n, size_t size, gfp_t flags, int node, kmalloc_token_t token)
 {
 	size_t bytes;
 
 	if (unlikely(check_mul_overflow(n, size, &bytes)))
 		return NULL;
 
-	return kvmalloc_node_noprof(bytes, flags, node);
+	return __kvmalloc_node_noprof(PASS_BUCKET_PARAMS(bytes, NULL), flags, node, token);
 }
-
+#define kvmalloc_array_node_noprof(...)		_kvmalloc_array_node_noprof(__VA_ARGS__, __kmalloc_token(__VA_ARGS__))
 #define kvmalloc_array_noprof(...)		kvmalloc_array_node_noprof(__VA_ARGS__, NUMA_NO_NODE)
 #define kvcalloc_node_noprof(_n,_s,_f,_node)	kvmalloc_array_node_noprof(_n,_s,(_f)|__GFP_ZERO,_node)
 #define kvcalloc_noprof(...)			kvcalloc_node_noprof(__VA_ARGS__, NUMA_NO_NODE)
diff --git a/kernel/configs/hardening.config b/kernel/configs/hardening.config
index 64caaf997fc0..df4fba56a3fd 100644
--- a/kernel/configs/hardening.config
+++ b/kernel/configs/hardening.config
@@ -22,7 +22,7 @@ CONFIG_SLAB_FREELIST_RANDOM=y
 CONFIG_SLAB_FREELIST_HARDENED=y
 CONFIG_SLAB_BUCKETS=y
 CONFIG_SHUFFLE_PAGE_ALLOCATOR=y
-CONFIG_RANDOM_KMALLOC_CACHES=y
+CONFIG_PARTITION_KMALLOC_CACHES=y
 
 # Sanity check userspace page table mappings.
 CONFIG_PAGE_TABLE_CHECK=y
diff --git a/mm/Kconfig b/mm/Kconfig
index e443fe8cd6cf..f194ead443d4 100644
--- a/mm/Kconfig
+++ b/mm/Kconfig
@@ -284,22 +284,45 @@ config SLUB_CPU_PARTIAL
 	  which requires the taking of locks that may cause latency spikes.
 	  Typically one would choose no for a realtime system.
 
-config RANDOM_KMALLOC_CACHES
-	default n
+config PARTITION_KMALLOC_CACHES
 	depends on !SLUB_TINY
-	bool "Randomize slab caches for normal kmalloc"
+	bool "Partitioned slab caches for normal kmalloc"
 	help
-	  A hardening feature that creates multiple copies of slab caches for
-	  normal kmalloc allocation and makes kmalloc randomly pick one based
-	  on code address, which makes the attackers more difficult to spray
-	  vulnerable memory objects on the heap for the purpose of exploiting
-	  memory vulnerabilities.
+	  A hardening feature that creates multiple isolated copies of slab
+	  caches for normal kmalloc allocations. This makes it more difficult
+	  to exploit memory-safety vulnerabilities by attacking vulnerable
+	  co-located memory objects. Several modes are provided.
 
 	  Currently the number of copies is set to 16, a reasonably large value
 	  that effectively diverges the memory objects allocated for different
 	  subsystems or modules into different caches, at the expense of a
-	  limited degree of memory and CPU overhead that relates to hardware and
-	  system workload.
+	  limited degree of memory and CPU overhead that relates to hardware
+	  and system workload.
+
+choice
+	prompt "Partitioned slab cache mode"
+	depends on PARTITION_KMALLOC_CACHES
+	default TYPED_KMALLOC_CACHES
+	help
+	  Selects the slab cache partitioning mode.
+
+config RANDOM_KMALLOC_CACHES
+	bool "Randomize slab caches for normal kmalloc"
+	help
+	  Randomly pick a slab cache based on code address.
+
+config TYPED_KMALLOC_CACHES
+	bool "Type based slab cache selection for normal kmalloc"
+	depends on $(cc-option,-falloc-token-max=123)
+	help
+	  Rely on Clang's allocation tokens to choose a slab cache, where token
+	  IDs are derived from the allocated type.
+
+	  The current effectiveness of Clang's type inference can be judged by
+	  -Rpass=alloc-token, which provides diagnostics where (after dead-code
+	  elimination) type inference failed.
+
+endchoice
 
 endmenu # Slab allocator options
 
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 00034e37bc9f..76111257bbcc 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -214,7 +214,7 @@ static void test_cache_destroy(void)
 static inline size_t kmalloc_cache_alignment(size_t size)
 {
 	/* just to get ->align so no need to pass in the real caller */
-	enum kmalloc_cache_type type = kmalloc_type(GFP_KERNEL, 0);
+	enum kmalloc_cache_type type = kmalloc_type(GFP_KERNEL, __kmalloc_token(0));
 	return kmalloc_caches[type][__kmalloc_index(size, false)]->align;
 }
 
@@ -285,7 +285,7 @@ static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocat
 
 		if (is_kfence_address(alloc)) {
 			struct slab *slab = virt_to_slab(alloc);
-			enum kmalloc_cache_type type = kmalloc_type(GFP_KERNEL, _RET_IP_);
+			enum kmalloc_cache_type type = kmalloc_type(GFP_KERNEL, __kmalloc_token(size));
 			struct kmem_cache *s = test_cache ?:
 					kmalloc_caches[type][__kmalloc_index(size, false)];
 
diff --git a/mm/slab.h b/mm/slab.h
index 248b34c839b7..e956b59e0bd8 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -386,12 +386,12 @@ static inline unsigned int size_index_elem(unsigned int bytes)
  * KMALLOC_MAX_CACHE_SIZE and the caller must check that.
  */
 static inline struct kmem_cache *
-kmalloc_slab(size_t size, kmem_buckets *b, gfp_t flags, unsigned long caller)
+kmalloc_slab(size_t size, kmem_buckets *b, gfp_t flags, kmalloc_token_t token)
 {
 	unsigned int index;
 
 	if (!b)
-		b = &kmalloc_caches[kmalloc_type(flags, caller)];
+		b = &kmalloc_caches[kmalloc_type(flags, token)];
 	if (size <= 192)
 		index = kmalloc_size_index[size_index_elem(size)];
 	else
diff --git a/mm/slab_common.c b/mm/slab_common.c
index bfe7c40eeee1..6c826d50c819 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -741,7 +741,7 @@ size_t kmalloc_size_roundup(size_t size)
 		 * The flags don't matter since size_index is common to all.
 		 * Neither does the caller for just getting ->object_size.
 		 */
-		return kmalloc_slab(size, NULL, GFP_KERNEL, 0)->object_size;
+		return kmalloc_slab(size, NULL, GFP_KERNEL, __kmalloc_token(0))->object_size;
 	}
 
 	/* Above the smaller buckets, size is a multiple of page size. */
@@ -775,26 +775,26 @@ EXPORT_SYMBOL(kmalloc_size_roundup);
 #define KMALLOC_RCL_NAME(sz)
 #endif
 
-#ifdef CONFIG_RANDOM_KMALLOC_CACHES
-#define __KMALLOC_RANDOM_CONCAT(a, b) a ## b
-#define KMALLOC_RANDOM_NAME(N, sz) __KMALLOC_RANDOM_CONCAT(KMA_RAND_, N)(sz)
-#define KMA_RAND_1(sz)                  .name[KMALLOC_RANDOM_START +  1] = "kmalloc-rnd-01-" #sz,
-#define KMA_RAND_2(sz)  KMA_RAND_1(sz)  .name[KMALLOC_RANDOM_START +  2] = "kmalloc-rnd-02-" #sz,
-#define KMA_RAND_3(sz)  KMA_RAND_2(sz)  .name[KMALLOC_RANDOM_START +  3] = "kmalloc-rnd-03-" #sz,
-#define KMA_RAND_4(sz)  KMA_RAND_3(sz)  .name[KMALLOC_RANDOM_START +  4] = "kmalloc-rnd-04-" #sz,
-#define KMA_RAND_5(sz)  KMA_RAND_4(sz)  .name[KMALLOC_RANDOM_START +  5] = "kmalloc-rnd-05-" #sz,
-#define KMA_RAND_6(sz)  KMA_RAND_5(sz)  .name[KMALLOC_RANDOM_START +  6] = "kmalloc-rnd-06-" #sz,
-#define KMA_RAND_7(sz)  KMA_RAND_6(sz)  .name[KMALLOC_RANDOM_START +  7] = "kmalloc-rnd-07-" #sz,
-#define KMA_RAND_8(sz)  KMA_RAND_7(sz)  .name[KMALLOC_RANDOM_START +  8] = "kmalloc-rnd-08-" #sz,
-#define KMA_RAND_9(sz)  KMA_RAND_8(sz)  .name[KMALLOC_RANDOM_START +  9] = "kmalloc-rnd-09-" #sz,
-#define KMA_RAND_10(sz) KMA_RAND_9(sz)  .name[KMALLOC_RANDOM_START + 10] = "kmalloc-rnd-10-" #sz,
-#define KMA_RAND_11(sz) KMA_RAND_10(sz) .name[KMALLOC_RANDOM_START + 11] = "kmalloc-rnd-11-" #sz,
-#define KMA_RAND_12(sz) KMA_RAND_11(sz) .name[KMALLOC_RANDOM_START + 12] = "kmalloc-rnd-12-" #sz,
-#define KMA_RAND_13(sz) KMA_RAND_12(sz) .name[KMALLOC_RANDOM_START + 13] = "kmalloc-rnd-13-" #sz,
-#define KMA_RAND_14(sz) KMA_RAND_13(sz) .name[KMALLOC_RANDOM_START + 14] = "kmalloc-rnd-14-" #sz,
-#define KMA_RAND_15(sz) KMA_RAND_14(sz) .name[KMALLOC_RANDOM_START + 15] = "kmalloc-rnd-15-" #sz,
-#else // CONFIG_RANDOM_KMALLOC_CACHES
-#define KMALLOC_RANDOM_NAME(N, sz)
+#ifdef CONFIG_PARTITION_KMALLOC_CACHES
+#define __KMALLOC_PARTITION_CONCAT(a, b) a ## b
+#define KMALLOC_PARTITION_NAME(N, sz) __KMALLOC_PARTITION_CONCAT(KMA_PART_, N)(sz)
+#define KMA_PART_1(sz)                  .name[KMALLOC_PARTITION_START +  1] = "kmalloc-part-01-" #sz,
+#define KMA_PART_2(sz)  KMA_PART_1(sz)  .name[KMALLOC_PARTITION_START +  2] = "kmalloc-part-02-" #sz,
+#define KMA_PART_3(sz)  KMA_PART_2(sz)  .name[KMALLOC_PARTITION_START +  3] = "kmalloc-part-03-" #sz,
+#define KMA_PART_4(sz)  KMA_PART_3(sz)  .name[KMALLOC_PARTITION_START +  4] = "kmalloc-part-04-" #sz,
+#define KMA_PART_5(sz)  KMA_PART_4(sz)  .name[KMALLOC_PARTITION_START +  5] = "kmalloc-part-05-" #sz,
+#define KMA_PART_6(sz)  KMA_PART_5(sz)  .name[KMALLOC_PARTITION_START +  6] = "kmalloc-part-06-" #sz,
+#define KMA_PART_7(sz)  KMA_PART_6(sz)  .name[KMALLOC_PARTITION_START +  7] = "kmalloc-part-07-" #sz,
+#define KMA_PART_8(sz)  KMA_PART_7(sz)  .name[KMALLOC_PARTITION_START +  8] = "kmalloc-part-08-" #sz,
+#define KMA_PART_9(sz)  KMA_PART_8(sz)  .name[KMALLOC_PARTITION_START +  9] = "kmalloc-part-09-" #sz,
+#define KMA_PART_10(sz) KMA_PART_9(sz)  .name[KMALLOC_PARTITION_START + 10] = "kmalloc-part-10-" #sz,
+#define KMA_PART_11(sz) KMA_PART_10(sz) .name[KMALLOC_PARTITION_START + 11] = "kmalloc-part-11-" #sz,
+#define KMA_PART_12(sz) KMA_PART_11(sz) .name[KMALLOC_PARTITION_START + 12] = "kmalloc-part-12-" #sz,
+#define KMA_PART_13(sz) KMA_PART_12(sz) .name[KMALLOC_PARTITION_START + 13] = "kmalloc-part-13-" #sz,
+#define KMA_PART_14(sz) KMA_PART_13(sz) .name[KMALLOC_PARTITION_START + 14] = "kmalloc-part-14-" #sz,
+#define KMA_PART_15(sz) KMA_PART_14(sz) .name[KMALLOC_PARTITION_START + 15] = "kmalloc-part-15-" #sz,
+#else // CONFIG_PARTITION_KMALLOC_CACHES
+#define KMALLOC_PARTITION_NAME(N, sz)
 #endif
 
 #define INIT_KMALLOC_INFO(__size, __short_size)			\
@@ -803,7 +803,7 @@ EXPORT_SYMBOL(kmalloc_size_roundup);
 	KMALLOC_RCL_NAME(__short_size)				\
 	KMALLOC_CGROUP_NAME(__short_size)			\
 	KMALLOC_DMA_NAME(__short_size)				\
-	KMALLOC_RANDOM_NAME(RANDOM_KMALLOC_CACHES_NR, __short_size)	\
+	KMALLOC_PARTITION_NAME(PARTITION_KMALLOC_CACHES_NR, __short_size)	\
 	.size = __size,						\
 }
 
@@ -915,8 +915,8 @@ new_kmalloc_cache(int idx, enum kmalloc_cache_type type)
 		flags |= SLAB_CACHE_DMA;
 	}
 
-#ifdef CONFIG_RANDOM_KMALLOC_CACHES
-	if (type >= KMALLOC_RANDOM_START && type <= KMALLOC_RANDOM_END)
+#ifdef CONFIG_PARTITION_KMALLOC_CACHES
+	if (type >= KMALLOC_PARTITION_START && type <= KMALLOC_PARTITION_END)
 		flags |= SLAB_NO_MERGE;
 #endif
 
diff --git a/mm/slub.c b/mm/slub.c
index 30003763d224..d3c2beab0ea2 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -4344,7 +4344,7 @@ EXPORT_SYMBOL(__kmalloc_large_node_noprof);
 
 static __always_inline
 void *__do_kmalloc_node(size_t size, kmem_buckets *b, gfp_t flags, int node,
-			unsigned long caller)
+			unsigned long caller, kmalloc_token_t token)
 {
 	struct kmem_cache *s;
 	void *ret;
@@ -4359,29 +4359,29 @@ void *__do_kmalloc_node(size_t size, kmem_buckets *b, gfp_t flags, int node,
 	if (unlikely(!size))
 		return ZERO_SIZE_PTR;
 
-	s = kmalloc_slab(size, b, flags, caller);
+	s = kmalloc_slab(size, b, flags, token);
 
 	ret = slab_alloc_node(s, NULL, flags, node, caller, size);
 	ret = kasan_kmalloc(s, ret, size, flags);
 	trace_kmalloc(caller, ret, size, s->size, flags, node);
 	return ret;
 }
-void *__kmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node)
+void *__kmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node, kmalloc_token_t token)
 {
-	return __do_kmalloc_node(size, PASS_BUCKET_PARAM(b), flags, node, _RET_IP_);
+	return __do_kmalloc_node(size, PASS_BUCKET_PARAM(b), flags, node, _RET_IP_, token);
 }
 EXPORT_SYMBOL(__kmalloc_node_noprof);
 
-void *__kmalloc_noprof(size_t size, gfp_t flags)
+void *__kmalloc_noprof(size_t size, gfp_t flags, kmalloc_token_t token)
 {
-	return __do_kmalloc_node(size, NULL, flags, NUMA_NO_NODE, _RET_IP_);
+	return __do_kmalloc_node(size, NULL, flags, NUMA_NO_NODE, _RET_IP_, token);
 }
 EXPORT_SYMBOL(__kmalloc_noprof);
 
 void *__kmalloc_node_track_caller_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags,
-					 int node, unsigned long caller)
+					 int node, unsigned long caller, kmalloc_token_t token)
 {
-	return __do_kmalloc_node(size, PASS_BUCKET_PARAM(b), flags, node, caller);
+	return __do_kmalloc_node(size, PASS_BUCKET_PARAM(b), flags, node, caller, token);
 
 }
 EXPORT_SYMBOL(__kmalloc_node_track_caller_noprof);
@@ -5041,7 +5041,7 @@ static gfp_t kmalloc_gfp_adjust(gfp_t flags, size_t size)
  *
  * Return: pointer to the allocated memory of %NULL in case of failure
  */
-void *__kvmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node)
+void *__kvmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node, kmalloc_token_t token)
 {
 	void *ret;
 
@@ -5051,7 +5051,7 @@ void *__kvmalloc_node_noprof(DECL_BUCKET_PARAMS(size, b), gfp_t flags, int node)
 	 */
 	ret = __do_kmalloc_node(size, PASS_BUCKET_PARAM(b),
 				kmalloc_gfp_adjust(flags, size),
-				node, _RET_IP_);
+				node, _RET_IP_, token);
 	if (ret || size <= PAGE_SIZE)
 		return ret;
 
-- 
2.51.0.rc2.233.g662b1ed5c5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250825154505.1558444-1-elver%40google.com.
