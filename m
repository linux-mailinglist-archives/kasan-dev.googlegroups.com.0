Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQXRXWPQMGQEF7BOF3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 20E5E69ABE6
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 13:53:24 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id a10-20020a194f4a000000b004d1b23f2047sf278276lfk.20
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 04:53:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676638403; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ng8dCFt9Id90UEfA+28jObvmmdQFx+PTlf5i565dswUDoQuTKgx415TAnBMudlFT0P
         9xb7S2cqondlXUhQ72/wjJhrGbCdFmY27aYXsoW8JwuY37Beqn4Fp2a5XiZx6RpxqB1m
         vk5HTWt9qXjtqxhczUdT2cvv4qXO8IaPhqm/3JyVmJJkkjxX+jHNm9LyFeyb25rzRfUN
         Z2HGvo8WD2p3Ov4xJjTss+lRQzk2fVygcPmKz0wBjIaC7tidGby5UCl4RCGA6fYaU/2w
         5c/vFpPTuJeJZ2Xz/P0d9pswnTtUDVpyQLq8ywE/S/qSkeoYgX0jxMAPbjsgHRNwlJSP
         etVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=z9okXul03VtfO6qC+QM3Duvn95v+2qf3rmKRty0uiRk=;
        b=PYH8bcKD2dT2OMLDAcikO7pGYnZL87iU8rqYLTfIyeuBesoxnL1dGzEifFkgK6K7nA
         fEDN9YBHc6u7PYX9mbOkkG7X1+FQ6qJOwMk7+fVfNsARClbOJXfilMA/TJPdz5gBE/2w
         WJneg+VPBC6edlan0mIr+GGpvs76d/9GGUB1OfTCb6lurb9XROClzDHRdBlRccSX7Y18
         doe9g0Ndqy/8Isg+Iuypxv+BYtJ3n3NzR06h2DGtFU7+GsaiIX1aPtHV8jGxMctisJsi
         nyQBGvqnxDsyMXTn7ekT/bwDchaYIbx2Zhq75Y9VzRvat5B0yUJM5qfl/In/jV6Ac+Zb
         t+4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BVGRp9vY;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=z9okXul03VtfO6qC+QM3Duvn95v+2qf3rmKRty0uiRk=;
        b=jrQAriKz6Bd2pC7b0jU/calvGWskUow/A4QGl+byK8bYSf7PnQ8f0B9g0ADptSTHH0
         TiTQQbz2+px3ogne9VhiwROD7g9wetgomLp4ItdVFgIVKG6NQJBl1qLhsVcy/zEE2utj
         HUl+AV8iLGHkRsa+qOg1atpFIlhSwqemOAAYqC5QU4o9q+R1PujBcrr30UzpiOCV6C5g
         hPowt+/F0jsDDDNimNk9H/CBUZypDtlsqwAHC0E2BuR/HpzSfQNYs76esWnx6jswxlyD
         sGAsZD1Yt51zMJfpwrrRCVDf9cF2rrctsi4oPBIHAbmNwNsJ2Jkgxpb/rdkmqAxScC/u
         uTEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=z9okXul03VtfO6qC+QM3Duvn95v+2qf3rmKRty0uiRk=;
        b=vvtqfrGR3jS+AVfwjWaabGu5rujcypNsPzQxrVNYDFGTo1k4VqPkk7HwFTkBLgciVw
         cS3qzVomSt7s4sFyVq7Jc3cnMmnBFmkkvo+/3DBeBVkgn+qaCHgAxNbwlZyFd08/f6b2
         eaitCPMRTamawdr8vEjD5hN4OjbvFSXf/NUKsSwEDj3LoSVrFvj4w7QzvZ0UKVHNLZq+
         i1utdSvQ1GHz0AAEgN/eDopX47hBaCQDp4f2ryGgPA1HkYJPYjygQbPoP4YXv7yzVZqs
         9eKv29EGT1vhlFFaRygvmvJ3O/xzhv+OJf+JqkM7Iogp71fdFBqUODi1q0SAQgLnae12
         FwWw==
X-Gm-Message-State: AO0yUKWLVMsguU+U63/V+ij/RwQY7+LMoqiRFzBgTjujqgYUHjJTc/TE
	NHev8XaQhY6OA1aGlQD5shk=
X-Google-Smtp-Source: AK7set8CIKs1YLwNj5WHzHgGtgRRRmYFZPRbRL2MWSzMzQerzvA+xZKITDlzvACV1pJuUemaKQNirw==
X-Received: by 2002:a2e:a22c:0:b0:294:7598:c84a with SMTP id i12-20020a2ea22c000000b002947598c84amr486558ljm.0.1676638403029;
        Fri, 17 Feb 2023 04:53:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e1d:b0:4db:3331:2b29 with SMTP id
 i29-20020a0565123e1d00b004db33312b29ls521480lfv.0.-pod-prod-gmail; Fri, 17
 Feb 2023 04:53:18 -0800 (PST)
X-Received: by 2002:ac2:4ac4:0:b0:4db:3605:9bdd with SMTP id m4-20020ac24ac4000000b004db36059bddmr2641799lfp.5.1676638398376;
        Fri, 17 Feb 2023 04:53:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676638398; cv=none;
        d=google.com; s=arc-20160816;
        b=uP2WvGWCOyK+BG9CLal7q7X09CtfIKzzcc1tTJYfruOQac4OxYPnkwmmh3oful1pfA
         IiP8++9OzJlsqGmoaxCJXUUDCCpTab+PwCwAsmi8HA5my9Os/iz38Qw7uUru/yePlewD
         cGrmHiefplYo2HKBVYX7AY7/eii4ORBpP/0dQ2iNPe7em7QlaCj2o3oEcLsAjUFl61bS
         eiS2EcvNUtK7gpIfTkYZOUMoItr3PPaWJf+sX4OeOOYihUw+jvMpr5035A+ZhzzPcY+M
         0XkhIQ/MpXXztC0jK6433e+w3Up5u/dwVmf7ykKte8Xn7jEr+PU18oEkq25Byhzcx2o4
         M/zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Ulgx+po/trB+4FXQcLmj6nxw3N0m6LL1KXnQpc+SYhI=;
        b=JRopa2SOyK6KYK38PKRgqL6OjAJALGmBS4eDeVh7UOzfCRAp8CccESzeT3BFadW/kV
         c8uQmD8JH3zuIGvcMQ6v0GinGTep8kKW2pLsOMr4TqAwPkH37TKgVUTOuTM00CN2Oz51
         66cNM1hC5wl637EnA90fFNv1jOAjDLrCvj0Q6CSTlRoT8G5SlRO7+a6YwP18+eTjhA5u
         oL06t+NsI+LN2eEtIiWmCMjlJTTh+VZvGUW40nrnezdDhzlB4rXTVTrnGZ+6ooIz0xkZ
         g16cbeLWOvL7geQbyOp3E9YXV0pg8h1Xqa6Sin/jwipKG2cfCTuA4ubhXYSOc1GIhB5P
         EbQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=BVGRp9vY;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id h16-20020a0565123c9000b004dc818e448asi52958lfv.3.2023.02.17.04.53.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Feb 2023 04:53:18 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id u2so437217wrs.0
        for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 04:53:18 -0800 (PST)
X-Received: by 2002:adf:fb92:0:b0:2c5:5933:1752 with SMTP id a18-20020adffb92000000b002c559331752mr700692wrr.52.1676638397783;
        Fri, 17 Feb 2023 04:53:17 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:34a3:b9c:4ef:ef85])
        by smtp.gmail.com with ESMTPSA id s17-20020a5d4251000000b002c6e8cb612fsm1050348wrr.92.2023.02.17.04.53.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 Feb 2023 04:53:17 -0800 (PST)
Date: Fri, 17 Feb 2023 13:53:10 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@kernel.org>, Jakub Jelinek <jakub@redhat.com>,
	linux-toolchains@vger.kernel.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-kbuild@vger.kernel.org
Subject: [PATCH -tip v4 4/4] kasan, x86: Don't rename memintrinsics in
 uninstrumented files
Message-ID: <Y+94tm7xoeTGqPgs@elver.google.com>
References: <20230216234522.3757369-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230216234522.3757369-1-elver@google.com>
User-Agent: Mutt/2.2.9 (2022-11-12)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=BVGRp9vY;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

Now that memcpy/memset/memmove are no longer overridden by KASAN, we can
just use the normal symbol names in uninstrumented files.

Drop the preprocessor redefinitions.

Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* New patch.
---
 arch/x86/include/asm/string_64.h | 19 -------------------
 1 file changed, 19 deletions(-)

diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/string_64.h
index 888731ccf1f6..c1e14cee0722 100644
--- a/arch/x86/include/asm/string_64.h
+++ b/arch/x86/include/asm/string_64.h
@@ -85,25 +85,6 @@ char *strcpy(char *dest, const char *src);
 char *strcat(char *dest, const char *src);
 int strcmp(const char *cs, const char *ct);
 
-#if (defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__))
-/*
- * For files that not instrumented (e.g. mm/slub.c) we
- * should use not instrumented version of mem* functions.
- */
-
-#undef memcpy
-#define memcpy(dst, src, len) __memcpy(dst, src, len)
-#undef memmove
-#define memmove(dst, src, len) __memmove(dst, src, len)
-#undef memset
-#define memset(s, c, n) __memset(s, c, n)
-
-#ifndef __NO_FORTIFY
-#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
-#endif
-
-#endif
-
 #ifdef CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE
 #define __HAVE_ARCH_MEMCPY_FLUSHCACHE 1
 void __memcpy_flushcache(void *dst, const void *src, size_t cnt);
-- 
2.39.2.637.g21b0678d19-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y%2B94tm7xoeTGqPgs%40elver.google.com.
