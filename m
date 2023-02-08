Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIW2R6PQMGQECYRI7II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id ACC2168F747
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 19:42:44 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id u3-20020a056a00124300b0056d4ab0c7cbsf10172495pfi.7
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 10:42:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675881763; cv=pass;
        d=google.com; s=arc-20160816;
        b=EKiX6rTJT0P87fCjO7Jiuui6sgQzAtLA3DIKSrEajTcKT4aoImEv9Xw+ndy/8bF+Ek
         Eb9ol7UUoUwVU6LhU+CxLNvMoNWqlrwFf7WNJEMsi/9Mey7py6Sxu50RDgxd2nFBaz6R
         t5kOGoXFBm+RWS+wSSyelkJx++3fJOogNKgMyiSCTdMPZHBHFk55U6Jw5//kSxzPmaAr
         w1ibBpzUenWkKzMbycEfUbOzSPeVjpNZziTkSjFjLwxSeM7vtMNTYZXnh35f1VuDerEd
         s+R7WwywCzSiG6IKFPec2IyGgF21wULxzJd5EiqT7jpUhLCTMRDBzby3NFQCA55U4Bji
         0fhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=ReTZ0KFfSXf5aQAuKyEbnGkzBkiqgHfJYRc+6pEy4MQ=;
        b=a2YiPhoS9yw2v6SCcStkVz67267JjQZ1pc/nEmmN1MH1NS6UoFdU7Z1xURDeHYCsAk
         87dacm0DopMVuv/TWsLF8tLmEhp9GX4cTrk5WfJUy6rcxdMnTtI7Ws2IbUGXN8yZzqNH
         tpNalmwfRMakZS8nEA6C2EaKvxKkv5wtXCiKsIhFXklDJr93eVF9GBlUw09+oC64UMrh
         G4sq/VN+jYrhFVFlRVQO2Wfhesw63S69PaSBbTYh03o8VMM0kZVCBeFjRAYAJ3zxua4Z
         9jUVTcRnla3jHtFbm4RrD4KQ2RzSJ+FK3ord7+9MKG4WIkTYTCnDK2yVh5byhZDaKB+i
         6xJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HxBkYsCy;
       spf=pass (google.com: domain of 3io3jywukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3IO3jYwUKCa8TakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ReTZ0KFfSXf5aQAuKyEbnGkzBkiqgHfJYRc+6pEy4MQ=;
        b=PiaLY3CaJ+UktHGDD753isRT4JrKNxvp7487X211LpMMW7kvxddLHCUgGk3d3M3c62
         7cM+AlbKHoPjC2d6zOWzlF75zA4Qw3m1IZVI57RgGRHrRUb5tPn6ajfm3RLPwlv8hKXR
         BvgzN/uoSxXcTM373quGR/XFFBMKjDeETG9/cW32oicwrwhgsBH2hCMMMaQgRe3J2lMf
         x6zpYx70v/NCaTsf6wHczjycLAViwFeAOnlc4aeivCfukqkmFA4cvrJy67uiZj1p7ap6
         gL76sM9nA57pDbbCgGcX42HAAoh5xjEyUVnrBAdbbAiLahiw4GhG96aYCcJLTsbCxpeF
         Yhvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ReTZ0KFfSXf5aQAuKyEbnGkzBkiqgHfJYRc+6pEy4MQ=;
        b=HdPUtU9v13ugh5+uePcpH7l13GTn+2xzTdoZE/nkMMAmzijF6qlbknFZE2sz1AoONy
         oOj0ic2cSLF2aFhutGIzPx5I4IRK/LMWPe4+P7UMo1SIt8mFPaSfmeiGX5yzqEp8rqyo
         HPZwc/4cw+PyikLhhHtt/Va9CZjLjIhgVucyxgefmRlHI1njiLLlPf823SNFVPyUh63u
         xZAd9Fwmv3n5j7hMce4HQAWbaj032fAohverPrtXxGXPUOAsfEk1bCtSurVrkXem2+5M
         vGe6x18pe0noxCdPTMjg9V5QY1kaPXvlHB13RL2NeAWnLpfzS7D1+Cr4rGlk3Bnk46Av
         Y8YA==
X-Gm-Message-State: AO0yUKUnyAL8wLb9RFTNDXFGtD9iZ+qAk/1EU4jsyATN/mumu/FHbj8d
	AVdyAoEMCxd2cTjv7otrI4o=
X-Google-Smtp-Source: AK7set83YnFRfTkX2mXNoSkKsyezAJwCm6x/14S5GlbP0qXXRqy31hyx/W8D0iVGnEaKEU2and0mpQ==
X-Received: by 2002:a17:90a:ad85:b0:230:d1d5:2041 with SMTP id s5-20020a17090aad8500b00230d1d52041mr1094087pjq.109.1675881762817;
        Wed, 08 Feb 2023 10:42:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e290:b0:226:e7:18f9 with SMTP id d16-20020a17090ae29000b0022600e718f9ls3270912pjz.0.-pod-canary-gmail;
 Wed, 08 Feb 2023 10:42:42 -0800 (PST)
X-Received: by 2002:a17:90b:38c5:b0:231:27d3:6b72 with SMTP id nn5-20020a17090b38c500b0023127d36b72mr593572pjb.24.1675881761950;
        Wed, 08 Feb 2023 10:42:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675881761; cv=none;
        d=google.com; s=arc-20160816;
        b=DxhM6cGjZHqyh/PrmQQV3eISTKKM4zuAFYDFXp3LZ8XCd/qR5goZH74XBoiMK4hUcW
         bvuwdv8tOoY/+z0+Js5QBF8ZgAg5vzr3rqvPdhGzqUD46uHK2+uQJ0YKc1MjM+10sh9J
         //qZbWA+iL5V+PodSbDtKEV+EmkSzaCwFs4iiSFL+Am7/yqPS6hRJKNqSG9cRECpBOC8
         5dLCzAjQjRL+6c3RB7G0bDOo+MMNnhptWZSppZ0ttI56ZlDWPxonmXdpcT8GYXtVdzVG
         QtUdT3UbI6XFLkYKyjJNRXQprKfmrEtnmwDH5nzl0iiAVDzT6gRZaHvU85HktH3/PSJY
         P9Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=muGKsBQpDMjO2rXBhVjlNe2+4h4S1u+JGQBqWajmnMY=;
        b=QHorwL/qKGTfwSOe761y/t+7u0TUine2R4wfyrQUOKqHhLR7f8GGFpZazSuwxOruL7
         jIZlzMKkGawasg5Ngyf3w3DQPMJbUzMiKurA2TL8Pg1unUpMelc1Srhtdp8san0/ILV9
         B+EHXjOmvaSe3Ihrp5/x+KmaSKjpt69lh+y6QvhbBFYpfL4cNzcuzNGYjrFK4KnPm4SB
         52a+MBq1R9EF7fsRoxZGv5GfyTOE6TaQLIQ7QaaJiLmmGKGV6qskc1QNJkG35G8PNshZ
         1ECkQE53e7+/+bMQcDSY1ohBv5GBOzdR+5zdAbi6Eh/ErlkV5rIVCD+tQp93U1tnpWnh
         XYSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HxBkYsCy;
       spf=pass (google.com: domain of 3io3jywukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3IO3jYwUKCa8TakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id c24-20020a17090a8d1800b002309f8d0078si561806pjo.0.2023.02.08.10.42.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Feb 2023 10:42:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3io3jywukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-5261de2841fso141582557b3.7
        for <kasan-dev@googlegroups.com>; Wed, 08 Feb 2023 10:42:41 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:a0ba:1bc4:8b19:5b22])
 (user=elver job=sendgmr) by 2002:a81:1312:0:b0:528:37bd:c122 with SMTP id
 18-20020a811312000000b0052837bdc122mr10ywt.5.1675881760758; Wed, 08 Feb 2023
 10:42:40 -0800 (PST)
Date: Wed,  8 Feb 2023 19:42:03 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.1.519.gcb327c4b5f-goog
Message-ID: <20230208184203.2260394-1-elver@google.com>
Subject: [PATCH -tip] kasan: Emit different calls for instrumentable memintrinsics
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Nicolas Schier <nicolas@fjasle.eu>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Ingo Molnar <mingo@kernel.org>, Tony Lindgren <tony@atomide.com>, 
	Ulf Hansson <ulf.hansson@linaro.org>, linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HxBkYsCy;       spf=pass
 (google.com: domain of 3io3jywukca8taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3IO3jYwUKCa8TakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
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

GCC does not yet have similar support.

Use it to regain KASAN instrumentation of memcpy/memset/memmove on
architectures that require noinstr to be really free from instrumented
mem*() functions (all GENERIC_ENTRY architectures).

Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
Signed-off-by: Marco Elver <elver@google.com>
---

The Fixes tag is just there to show the dependency, and that people
shouldn't apply this patch without 69d4c0d32186.

---
 scripts/Makefile.kasan | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index b9e94c5e7097..78336b04c077 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -38,6 +38,13 @@ endif
 
 CFLAGS_KASAN += $(call cc-param,asan-stack=$(stack_enable))
 
+ifdef CONFIG_GENERIC_ENTRY
+# Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
+# instead. With compilers that don't support this option, compiler-inserted
+# memintrinsics won't be checked by KASAN.
+CFLAGS_KASAN += $(call cc-param,asan-kernel-mem-intrinsic-prefix)
+endif
+
 endif # CONFIG_KASAN_GENERIC
 
 ifdef CONFIG_KASAN_SW_TAGS
-- 
2.39.1.519.gcb327c4b5f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230208184203.2260394-1-elver%40google.com.
