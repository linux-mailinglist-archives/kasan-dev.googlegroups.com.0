Return-Path: <kasan-dev+bncBC7OBJGL2MHBB75TVKPQMGQENABRHQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id F21BC695181
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 21:13:52 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id r17-20020a2eb891000000b00290658792cesf3188602ljp.4
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 12:13:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676319232; cv=pass;
        d=google.com; s=arc-20160816;
        b=TV0adaapho25vZ5Ng5YY1agU+gOb8CknkYu1TXWL88HGz7IVswFcEfC8Yt0NkYUapY
         gpcES1gCNQuNTL3jtxoiGSCOgOMx387k5MgtR3cKOPJGQ2PBhirtMqoNI2WLR60iThyb
         9hCu/z3SCgNvbHG+cyc0EbSXsFnK7tDYqYD744l823z3UQ1mhUqE2g/p0HPEmF5dYJVP
         wx8KyADzRKFOjNKt/KESBAuJ9YlDMAu4sbJxLCiXDJ1h3/Ii4qEyR3iQ8aAzBmT/nPQ4
         LulPt5FlaK0+il2bacHY6A8Ks4CNbfi6Nk5SeteCTENnQEIVNGINt/azTJz2dvGCqtK4
         wN4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=NZ/3xmoxAK8zBk6f2fyf4NgN98JyziinizyhNc3BFgE=;
        b=FYUPRaAqKijZ2Q9D/VpI7eIat+G8Jas2FKGZCspcQsv0szn0V48mhi7ehp0cGM7KBB
         mveHo+tZv3TLKj6A5rv5ZthXVXxOPH0d9+qwbRUCgA0MV8tKMfL8hGm1ZJoSwQD+7Ieg
         QuI2mmrPHYX3d4L6YoxRGmBXKQefA6pnYsC5lHfazT5A9AodN3ZYNlC1ooFFoFIFCJFs
         5Z4LPNm3PpGZBoUB4GW03KkG20+BQFddtMZMbKiqnF0+QVsysFsBSFMxkOTXPi2uSnAq
         ODaHqu018iYblnZaY3iFDkibpOVZ4BlJis2hJZMziFRzzq1z6xzF+lQdIj2fXHTcEBax
         8QjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E84LspmK;
       spf=pass (google.com: domain of 3_znqywukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3_ZnqYwUKCQIgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NZ/3xmoxAK8zBk6f2fyf4NgN98JyziinizyhNc3BFgE=;
        b=jjpuVIblTOuusDPivqJdoTrW4HusCR1dEGF4ab0HKv4xfh+xdcS7biJdkY2u1hiK0B
         tsUEpdjRqQrjMOdFsTGkZFuUmUwAgDJicz/cuGwxMj62/hwSfovcC78Qwh0bhx352npQ
         d+ZeKRxCbUx3GXoD8Bofz7L5JhAlWF8Nr97lFZiOYwmdcr+Qi/hmS9ItvMWQ2wl6q4yl
         rSIzl6PbnrNZNxCp74P/SHemA7DR8zCTdX6l+UhBE9sHuMX5zebgPypab8ChJd0ZOYpL
         9VD+bbd2jPyD3OIutEMinWn1P9yvjDGh9I3ituf6WYhw92q4/7OGE26zaYyhNE62omfQ
         xXgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NZ/3xmoxAK8zBk6f2fyf4NgN98JyziinizyhNc3BFgE=;
        b=iRWbs4IGG5XiLAlGh021/Xhysrsz/yD3+qLvnCsFR/WMxA36yv1orjiVHnYY2a7xQ/
         4qN9vWfjygCXvmhW79hLNQmv2+37dxvnf7Xm68ZVF2I5w7D4ysRokm8yoc872OaiRee+
         7bqJDLwLXEGRoPe2zHX8xXwri5RZFBjfWVE2izPygHf8QftuvIRMNqYy4KpPxZvjhOv3
         9MC6VWmCEX03Bddm8KlZ3YbulxdzKtr3UIFjaud5p9mgyqWblD0+7gfPCE0haYdrpGCn
         gBmSuI2iB28rxcSuYRepgyiMjgwUaCVxJgkNx7ATO1rvXv0vNSzlfLxP3aaVwS8fdc4Q
         L0Og==
X-Gm-Message-State: AO0yUKVsd7lqHN7YgW1r3ZWQ5kruEQyBQaTttwnzoLvZeqy9rrxf593o
	UgD68bZetso3Wn7V4bfLuj4=
X-Google-Smtp-Source: AK7set/Ge5+87P4zIxufI7y3e90Y5GLhO4zW9O13WsNkdcF5ChKMNCFRR516/Dd+6U7dIy3T4rWxdg==
X-Received: by 2002:a05:6512:941:b0:4d5:ca43:7047 with SMTP id u1-20020a056512094100b004d5ca437047mr51486lft.10.1676319231966;
        Mon, 13 Feb 2023 12:13:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9b0e:0:b0:293:5310:5e0e with SMTP id u14-20020a2e9b0e000000b0029353105e0els381462lji.7.-pod-prod-gmail;
 Mon, 13 Feb 2023 12:13:50 -0800 (PST)
X-Received: by 2002:a2e:a592:0:b0:28d:cca5:2193 with SMTP id m18-20020a2ea592000000b0028dcca52193mr8948810ljp.53.1676319230116;
        Mon, 13 Feb 2023 12:13:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676319230; cv=none;
        d=google.com; s=arc-20160816;
        b=Jw2Vw3eVot4dm6d998zTcDhjCGR/PGo1dz2cFAeOZP8Fd2wGP0Mg2JK50VIkpT5JOR
         tc2Gn8HiL2xoOzQ5DM8qcOtGEaN/9UJVzTM5XF+KYnov267V5E3wqDk9CpcaC4VosRb6
         Eswzqm8D//yCNrGPShtKmfKuDEId/nYorUnDUyXwkY19764ceFsH+2JfHoeV3z5pTuw3
         tsllWYJiJsYNAwyfz4ID9GxSYfJ+GPmjnnfxoOCrtMrOrFxAOgx7w3CWN8Q89h8Dklbh
         7jyg3wiRtTiYKh8I3NoDc1T7xqhYgIAwsMHtqb219W2WSCqS0GuT65TB74C9LslnHxIi
         kpbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=VhrJl5YJ7d2XgMTj7m/kCtzHq/X4U46pZjqetmx6EIU=;
        b=u245rcM81ndHbXoAOWs1NUAgkncHfqAXwLwL9qFIFN+yCbS1f0/kJEnDb742ZxvZLs
         VeFc7VE4xKgffKt6wrmpR8mac/V1T8Sxu12dENb9X/edpztiWrBZQC86zLLGmEqbnMAZ
         39QTN7Pm5Ml7Wbuy9LORBu8wx8b3fstQBHbGmTktCOCsoUaGKP5oTPIWQXtLPIR9BsEr
         nSF1hFuJ7qbSe4wMtivLnxLwx8m4tEyQab5B3zcIZ2BThHjwFcmE90mKCk0KUQVvhGRh
         5iP7rZZA7vPIKJKxC/FNGHnSlF3ZLe2owz2PNNUBwLsDR4uXPvmSQnNe2q9ZPtTn/i6a
         UiAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E84LspmK;
       spf=pass (google.com: domain of 3_znqywukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3_ZnqYwUKCQIgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id s15-20020a2eb8cf000000b00286e157db47si604066ljp.6.2023.02.13.12.13.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 12:13:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_znqywukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id bo27-20020a0564020b3b00b004a6c2f6a226so8424764edb.15
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 12:13:50 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:6cba:3834:3b50:a0b2])
 (user=elver job=sendgmr) by 2002:a50:ab5b:0:b0:4ab:c702:656 with SMTP id
 t27-20020a50ab5b000000b004abc7020656mr4694edc.1.1676319229479; Mon, 13 Feb
 2023 12:13:49 -0800 (PST)
Date: Mon, 13 Feb 2023 21:13:35 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.1.581.gbfd45094c4-goog
Message-ID: <20230213201334.1494626-1-elver@google.com>
Subject: [PATCH -tip v3] kasan: Emit different calls for instrumentable memintrinsics
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Nicolas Schier <nicolas@fjasle.eu>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Ingo Molnar <mingo@kernel.org>, Tony Lindgren <tony@atomide.com>, 
	Ulf Hansson <ulf.hansson@linaro.org>, Jakub Jelinek <jakub@redhat.com>, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=E84LspmK;       spf=pass
 (google.com: domain of 3_znqywukcqignxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3_ZnqYwUKCQIgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
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

Clang 15 will provide an option to prefix calls to memcpy/memset/memmove
with __asan_ in instrumented functions: https://reviews.llvm.org/D122724

GCC will add support in future:
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108777

Use it to regain KASAN instrumentation of memcpy/memset/memmove on
architectures that require noinstr to be really free from instrumented
mem*() functions (all GENERIC_ENTRY architectures).

Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Resend with actual fix.

v2:
* Use asan-kernel-mem-intrinsic-prefix=1, so that once GCC supports the
  param, it also works there (it needs the =1).

The Fixes tag is just there to show the dependency, and that people
shouldn't apply this patch without 69d4c0d32186.
---
 scripts/Makefile.kasan | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index b9e94c5e7097..3b35a88af60d 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -38,6 +38,13 @@ endif
 
 CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
 
+ifdef CONFIG_GENERIC_ENTRY
+# Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
+# instead. With compilers that don't support this option, compiler-inserted
+# memintrinsics won't be checked by KASAN.
+CFLAGS_KASAN += $(call cc-param,asan-kernel-mem-intrinsic-prefix=1)
+endif
+
 endif # CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_SW_TAGS
-- 
2.39.1.581.gbfd45094c4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230213201334.1494626-1-elver%40google.com.
