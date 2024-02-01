Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSNP5WWQMGQE2BZONEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E0298452D3
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Feb 2024 09:35:23 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2d07b30ba0csf1994611fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Feb 2024 00:35:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706776523; cv=pass;
        d=google.com; s=arc-20160816;
        b=T8rZLq5HkWFEzC94h7Q1bBqWAaCQQ4xLvmyQnIu1jusxlTUFyD2SiglRvDZUkbQoOP
         Njv8Ub8Kl6fWDpzy7QxjahIMNNAMPEZxg0XK5HpUQRLXTRbHWYCRSGacPlSrmxVg7GvK
         ATESiYYYxWKm+jtTRjUi19GmtEWeWAIfkE4MVIuJ++lAAecbF2VXtSW+TLVWCcGamzJ9
         E20+F9ZRK08wN9uv/ARes5Fo9Q092Uj//JkrK4kgRDch4/NCy1TA43ijqUXHuy03OSno
         2R0BuAsnDgiTC9aPVMGcxDBVh1F/bxH+PSdD1/57lsLMF9xEtfD1j9kLYRvGh1vcSEHQ
         E8Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=NGy6J443Jplzd3o1IBNilKbN/ci2b2/wrW4Pk0Q0f7w=;
        fh=+ZaWucz3Bwb+RljXxNjqmoUiLtlUpKsqWo9dmjHVi10=;
        b=nMYOFsrjFYll7WxiMMJ+xXWxHZNQXlg/TmfRkCgSatnOlVa8UytbZbsvzA8FPn91DW
         uM7iDyzmu1rOiwGBAz8fNf/CkgUxnm2nkvQ9Omo+RkO5DOW1HWc3764nOk4/uUH1eIaZ
         Oe4H4gGzcW44/Eq3gXrIR/KyURVxolAYH1Eey9rk13VWRAxXXm71OF6DjsBIEnXYYc2r
         WMbp2d5SPE9doMDam6i7n62OpIcXuZQYplZ4RH+MSMU5prl/ZE8QAfsKxwS85q6Oubl/
         ODPwt8fWMKf8FaBbk5bgS10Sljc0MPwll0XF7rAgPC4iTw6qY7QnI1ohxHf3wJDDkxx0
         cC+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="ww8/4wtc";
       spf=pass (google.com: domain of 3x1e7zqukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3x1e7ZQUKCZg6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706776523; x=1707381323; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NGy6J443Jplzd3o1IBNilKbN/ci2b2/wrW4Pk0Q0f7w=;
        b=G7TOgE09Ey/dzKp7gw3a8qNmoUS4DJ2xM9YjVzK1bJbHWmI+CaV6KRQvqaPzJMwuGW
         gtlZGh4am3NKwJITJxn/WbuduBKQrCMb6cQdM+cj1+jh+MamOsPCFeE7Ivfa4uAlefyw
         41t/7T2ezlTKpQGdYGNM6jxea4mlha3HJAQV5Lb5Hg6u0BnINYFUjBGuT6pcdgNv4nOt
         wmtoX1gF9/6zQyFqifXgoi9voZRT3wd3kiw7uEJ+oj87pkSZEsZGF7AL+uz/ImUrejMr
         aezCTzqPbzODWuWWb0aK7J5Q3kKqVAgV1K61ZsLn5i/uZN9OFOry0J+fhgF3NZTtdh21
         v/pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706776523; x=1707381323;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NGy6J443Jplzd3o1IBNilKbN/ci2b2/wrW4Pk0Q0f7w=;
        b=MsN7quvqc+/XoUGCeDtWD7x3VrS2FRbfXBiazrAKTbTwl/vF4KxzRVkBoAfHahuPFw
         VF1gTLBue+N2SyhWUzA/ZXo2omAfnQW98mfdTUQ+41R+9uKG3S7DVXyKgwjp2pwAgsKK
         vp87NtUOkzLJ+Cgchad6z0twEdVT4WmXoj+xSr5mLB7FIE9TIP2vwqJsQ/c60NcHyx46
         zeiWc9EDb3oFoXWXnu+uWNynwwtoFuBKy6dFTkOspFwhWNC/PLxcxJ9gpEGmhWrJDMvM
         tdNXKQI1Tz4jRsZdbo/FuGWhZFHLNVpKqyW4jHA8c2/FcozKpDSANGeFlhv4so+c6Z2n
         v8pw==
X-Gm-Message-State: AOJu0YyG0obfIn5LY4zzyerwuLo9P4xYUge2hcIh/tjMc81A/O7Whc2U
	BJeLzXNdg2Ba9jnAOw5FjiXSoUP/aTWWOkTmX2DZHnnD/YpmEpFc
X-Google-Smtp-Source: AGHT+IEQiWzeL+TOpjAGHZcf4gJKbAjqqN22Z/MOvdE5fAhKkJu6UyG04yffVZUw/efCG3EulAEbTw==
X-Received: by 2002:a2e:9e52:0:b0:2cc:fc52:df9e with SMTP id g18-20020a2e9e52000000b002ccfc52df9emr3105097ljk.12.1706776522057;
        Thu, 01 Feb 2024 00:35:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:511d:b0:40f:222:db30 with SMTP id
 o29-20020a05600c511d00b0040f0222db30ls278098wms.2.-pod-prod-01-eu; Thu, 01
 Feb 2024 00:35:20 -0800 (PST)
X-Received: by 2002:a05:600c:5254:b0:40f:c1b7:2556 with SMTP id fc20-20020a05600c525400b0040fc1b72556mr192097wmb.11.1706776520180;
        Thu, 01 Feb 2024 00:35:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706776520; cv=none;
        d=google.com; s=arc-20160816;
        b=Pj+mp6ONsFo4theNBoUhhCUQFG76YHgeEeB27HPab21hMMmiIpzwGSdEEmhzmptZxw
         x7bKxIW472CrPoGc2hIaN69g+dVEuhJA7Wgg4YrYbeK42Z5YzKXfmnMxZVPxLT/fqtV1
         zkqWirj4uNw6o5kLLL6ppKgPc1Y6gF0vzt6Ww8bOS0nw+uRAxsXjxskIICwZ2qkvlGQx
         beTFPX6lprLq8JIUcbP8KAI6XHIJ6l6o4hciPYBoZLYfxNhS1Wr6d/zOw6ETl6711OAy
         h61ZcqUuGYe3o7VRLBGxoFM5jFA4YED1L3CTqQFBMGxej8DAjI9GsDQtDP3Y8dle3KpG
         yY8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=yDijPStjyNK8y9wipx4jasC/bHAVPAFiOvOL8ps5ECY=;
        fh=+ZaWucz3Bwb+RljXxNjqmoUiLtlUpKsqWo9dmjHVi10=;
        b=bsxpVZBKaA/yiXAzuZ+G2AEj4NraB/oIXEDWjJr8uKRU2XIyyXoDKkO/7GfE88vANG
         kJoSZ7Z9gxdBVzuA+9n4Iw1Zh1a70Z5YURZe4wc6riYYnSaiYQLj5nrPzB88uPwNhVDt
         RzU78DbAY0ds3M13Sqz8wWPSzuC3dPI2/57p1Lo6kczEqwv56TKjwSe3vaScFev76Vqu
         VERyMjD3CFsfpU8WWOTjliYLyZAE0hqC4s1vdPdv9GdG53QdXkmJrUgZ52iyCrXacF3Y
         5wvDdyKApbbXHhIzMLu/J9HXcoprH2M8bL/09q0GKlGvA6bboHYirrOs1bgPVhIp3rMZ
         04Dw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="ww8/4wtc";
       spf=pass (google.com: domain of 3x1e7zqukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3x1e7ZQUKCZg6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=0; AJvYcCXjZ0VsCUqwpBmlihN5lXSb1ZJdDDHEDn87WQZOfMBwIGuCDqq7jhRg13Ag1ypBJY3w1uA5sAOZ3+jaKsE6avT1d590X/xVCOYNBg==
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id k30-20020a05600c1c9e00b0040eefde0707si89532wms.1.2024.02.01.00.35.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Feb 2024 00:35:20 -0800 (PST)
Received-SPF: pass (google.com: domain of 3x1e7zqukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-55ef9f852daso334106a12.2
        for <kasan-dev@googlegroups.com>; Thu, 01 Feb 2024 00:35:20 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:c945:1806:ff53:36fa])
 (user=elver job=sendgmr) by 2002:a05:6402:44:b0:55f:2bd3:a896 with SMTP id
 f4-20020a056402004400b0055f2bd3a896mr10422edu.3.1706776519344; Thu, 01 Feb
 2024 00:35:19 -0800 (PST)
Date: Thu,  1 Feb 2024 09:31:35 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.43.0.429.g432eaa2c6b-goog
Message-ID: <20240201083259.1734865-1-elver@google.com>
Subject: [PATCH -mm] stackdepot: do not use flex_array_size() in memcpy()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Stephen Rothwell <sfr@canb.auug.org.au>, "Gustavo A . R . Silva" <gustavoars@kernel.org>, 
	Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="ww8/4wtc";       spf=pass
 (google.com: domain of 3x1e7zqukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3x1e7ZQUKCZg6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Since 113a61863ecb ("Makefile: Enable -Wstringop-overflow globally")
string overflow checking is enabled by default. Unfortunately the
compiler still isn't smart enough to always see that the size will never
overflow.

Specifically, in stackdepot, we have this before memcpy()'ing a
stacktrace:

  if (nr_entries > CONFIG_STACKDEPOT_MAX_FRAMES)
  	nr_entries = CONFIG_STACKDEPOT_MAX_FRAMES;
  ...
  memcpy(stack->entries, entries, flex_array_size(stack, entries, nr_entries));

Where 'entries' is an array of unsigned long, and STACKDEPOT_MAX_FRAMES
is 64 by default (configurable up to 256), thus the maximum size in
bytes (on 32-bit) would be 1024. For some reason the compiler (GCC
13.2.0) assumes that an overflow may be possible and flex_array_size()
can return SIZE_MAX (4294967295 on 32-bit), resulting in this warning:

 In function 'depot_alloc_stack',
     inlined from 'stack_depot_save_flags' at lib/stackdepot.c:688:4:
 arch/x86/include/asm/string_32.h:150:25: error: '__builtin_memcpy' specified bound 4294967295 exceeds maximum object size 2147483647 [-Werror=stringop-overflow=]
   150 | #define memcpy(t, f, n) __builtin_memcpy(t, f, n)
       |                         ^~~~~~~~~~~~~~~~~~~~~~~~~
 lib/stackdepot.c:459:9: note: in expansion of macro 'memcpy'
   459 |         memcpy(stack->entries, entries, flex_array_size(stack, entries, nr_entries));
       |         ^~~~~~
 cc1: all warnings being treated as errors

Silence the false positive warning by inlining the multiplication
ourselves.

Link: https://lore.kernel.org/all/20240201135747.18eca98e@canb.auug.org.au/
Fixes: d869d3fb362c ("stackdepot: use variable size records for non-evictable entries")
Reported-by: Stephen Rothwell <sfr@canb.auug.org.au>
Signed-off-by: Marco Elver <elver@google.com>
Cc: Gustavo A. R. Silva <gustavoars@kernel.org>
Cc: Kees Cook <keescook@chromium.org>
---
 lib/stackdepot.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 8f3b2c84ec2d..e6047f58ad62 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -456,7 +456,7 @@ depot_alloc_stack(unsigned long *entries, int nr_entries, u32 hash, depot_flags_
 	stack->hash = hash;
 	stack->size = nr_entries;
 	/* stack->handle is already filled in by depot_pop_free_pool(). */
-	memcpy(stack->entries, entries, flex_array_size(stack, entries, nr_entries));
+	memcpy(stack->entries, entries, nr_entries * sizeof(entries[0]));
 
 	if (flags & STACK_DEPOT_FLAG_GET) {
 		refcount_set(&stack->count, 1);
-- 
2.43.0.429.g432eaa2c6b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240201083259.1734865-1-elver%40google.com.
