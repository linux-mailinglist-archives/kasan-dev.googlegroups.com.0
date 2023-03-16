Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6FYZ2QAMGQEACB7JGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 34C906BDBED
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 23:47:21 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id i16-20020ac25b50000000b004b565e69540sf1346209lfp.12
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 15:47:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679006840; cv=pass;
        d=google.com; s=arc-20160816;
        b=smbXpD5hh4Vyo1bTOdURtSmgFIwMZhazP88kag3x4sO2zmS/8UP88Mb2npB9lfnrm+
         1HhjcG4lWCWCNCH4E70RtICfbXb2m6sYAs03C/VjcYRLG8k91Jcb4T80sQfqx5nMwQN/
         3QHmY7RBu45K/zTgmJyT/to+WdRs+CIjhkXzkpTHKAITxX3WfSG3G5AeF8Aon6b4Ajuq
         PEKkCwIAdDYlP1eubRvb5VlduatXlIJAegjYcVVGaLg3gOTtgf5nnB+QvgzKKBEKPRwY
         Yrazb99h9TRWjJJxEkkmOoudePKyd6Ka1BV0Td20ou9aWk3/rGiZS4mGO5J80bKg173x
         c/qA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=knburo5eD3E9CyhrQio0cm8VLCxX9SpPGcGow8p324o=;
        b=J3omcL4Ba0+crJxJ/jHVSKmUJH1BV1KcGZ3ZxoPYtekAuB5XykN7yzNu2m3Uc0E+vz
         +LVZ6g3u+FSeFDVsMruuXndaieh8hSqKVrpSOO0QS4uk99qA6nRPWMZkUSpIJXq2giLs
         otOKhu4fdoMMk5zaYZ3eAVcN47IaAvmQmNgK5GEwfjAquIpSbR8ul/cYdM3tLxl//mCP
         KBH+nly8WLiQXp7MJBdx152OncN5uWg2HuYiYoXzJdKGs+F2715v+yWFuryl6koyo4ak
         6xtf8DwUji3udscV/uBdamVo3A/Q3ThUghBI3ETNucd6itiXbG/05c+QbyF2AVcnF8YD
         Prxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=poi8gC8t;
       spf=pass (google.com: domain of 3dpwtzaukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3dpwTZAUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679006840;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=knburo5eD3E9CyhrQio0cm8VLCxX9SpPGcGow8p324o=;
        b=OymTelzeR4nNaVNC32dU3IUbKO42YFwVpgbKdQdb+ETcFvdc3ypfddVHTIDFhL8zOh
         bKdbhTdFEzPVJ9pTqjvVEoNHrsl9+c/DhHW+xKarJJZpNaj8yjX3ae06xxL6YLRMm2hT
         GEw+DjLZyAxG1WNZkQZS+vOBGpMvRi9L4Oioh0XEFQhchnjl649Txz/LDygP34PY72gr
         S10BJZSzQgmb0ZSYh4AqsRXV3wUBz+cKpoDjhJSG0OYDBoc74OpBkxSZaZPMyYnYiKGA
         wXQH/HgvjYf/zhL1mV1w/w1sMkBQprcq9Jj9IDo+4OXoTakhwjMKHxZ9KGQFugOAj6v+
         aDiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679006840;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=knburo5eD3E9CyhrQio0cm8VLCxX9SpPGcGow8p324o=;
        b=fU08EMWLGuCx1IJ2qP/SoVDXBBHVo7PLuu52Z2eDGQsu/7Cu3R+5XT9OhOLt/tG1kq
         TsNM5g84o5rQVDNapKoFud2uufujK/SuhN8hOVaU4VRvveXogeqKrIu9VkXtO88w58e4
         MCK3Amg7ZN5qMPxCy2c3xOuEcQvvNV16kOo6yy8eLZoHfpPaPOFelsBFYX/jNS0WmYVp
         3S9pOpcrEJNXZPhDXnikcfWXoYu4jrfPqbJEIjln3TpTZOD5brkYCEIylSmo0eIKYGly
         1PnRZq8T1FE/setc+utIqD848YwlHI7Kiqj66yrOac2G82o7FEnsxBhAbqOZhDWUsE7N
         tFow==
X-Gm-Message-State: AO0yUKVjiuVstwZl0Qj7+aSJ29pb2gPhcZBxDi2B9iRABaQO+A/prD7C
	RuY2SIONQdyaoZByPO8aOu5sWA==
X-Google-Smtp-Source: AK7set+/MMaQ+isUzH0B/AIYczB6QBlolTllYbigzJb7ARSo5e4eqjtF44pXUnDx6BobF9P6g0CBnw==
X-Received: by 2002:ac2:5193:0:b0:4e0:39f3:5b9b with SMTP id u19-20020ac25193000000b004e039f35b9bmr3667680lfi.0.1679006840382;
        Thu, 16 Mar 2023 15:47:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:15a4:b0:4e8:3ee1:db1a with SMTP id
 bp36-20020a05651215a400b004e83ee1db1als2606558lfb.0.-pod-prod-gmail; Thu, 16
 Mar 2023 15:47:18 -0700 (PDT)
X-Received: by 2002:ac2:5104:0:b0:4aa:e120:b431 with SMTP id q4-20020ac25104000000b004aae120b431mr3089543lfb.38.1679006838502;
        Thu, 16 Mar 2023 15:47:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679006838; cv=none;
        d=google.com; s=arc-20160816;
        b=vkY/V/bXSCq0ejBZNSVF/uEtMi21ZLzl7EvOqtaTpxacem4RnkWelzkKFDhyivmzQo
         AznafEZraftpTPenLpg09upLc+7NRDq3XpCiHGEjZhxBTjBbO5ip55umu3OddOhOuIUv
         3HA70wTeFBzzkaoIb//DbFVFCy65HTL1+JSUx69Mp5iBH6D2lPtiXGfGENLzvYciAxfz
         Rt0gPRRI4sm+LWxPE40RGLkYXIPJOzX2cc7htYoRqVL/mrZ0boopZJv8d0Y3ey+1EpGO
         6LP4ZagPWq8jfNl146/5y/cDZXZg4wXoomWIkyDpNegcdy/JhMWm0jSbzhII72mMJa1B
         eb9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=DKOoaD6Ra29v+G2EYQelA/9U1zSfLrdqKtsejRDWzBc=;
        b=bPZ1MzcS+6ZmFHCYJTDwq60/PljRi6a3ezHEHrB/QYl5E8LcZV0Vu0S1GN2WQqPWR6
         oEn9xb64stH7NJixv99M4ASfxX/KwHjyb8u/5PTw3hLpFRcsNI3REGjenaBNwenSzyon
         gdDqjmRnyG3ifxn2f8XdtufnC3EXueGLGPi7FxAbjqDZNq2N5AODW5F8vx1Tq1BgMvS9
         5odCb98Iy6WkeON34qvDATSdRSAmQ79X1l/2419DkXKGJgOSlRydSM6/BqR8QESk0gm9
         HcOZV+Qw/ynewJ24l4NyBqw//yZuLeV3TWGN9S8ZZ+01iqMryjcI7X64f/AI19+1YkYQ
         YCVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=poi8gC8t;
       spf=pass (google.com: domain of 3dpwtzaukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3dpwTZAUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id h1-20020a2ebc81000000b00299a6cef333si42300ljf.0.2023.03.16.15.47.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Mar 2023 15:47:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dpwtzaukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id r19-20020a50aad3000000b005002e950cd3so5039612edc.11
        for <kasan-dev@googlegroups.com>; Thu, 16 Mar 2023 15:47:18 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:f359:6b95:96e:1317])
 (user=elver job=sendgmr) by 2002:a17:907:7284:b0:931:6f5b:d27d with SMTP id
 dt4-20020a170907728400b009316f5bd27dmr669131ejc.0.1679006838228; Thu, 16 Mar
 2023 15:47:18 -0700 (PDT)
Date: Thu, 16 Mar 2023 23:47:05 +0100
In-Reply-To: <20230316224705.709984-1-elver@google.com>
Mime-Version: 1.0
References: <20230316224705.709984-1-elver@google.com>
X-Mailer: git-send-email 2.40.0.rc1.284.g88254d51c5-goog
Message-ID: <20230316224705.709984-2-elver@google.com>
Subject: [PATCH 2/2] kcsan: avoid passing -g for test
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Nathan Chancellor <nathan@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=poi8gC8t;       spf=pass
 (google.com: domain of 3dpwtzaukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3dpwTZAUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
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

Nathan reported that when building with GNU as and a version of clang
that defaults to DWARF5, the assembler will complain with:

  Error: non-constant .uleb128 is not supported

This is because `-g` defaults to the compiler debug info default. If the
assembler does not support some of the directives used, the above errors
occur. To fix, remove the explicit passing of `-g`.

All the test wants is that stack traces print valid function names, and
debug info is not required for that. (I currently cannot recall why I
added the explicit `-g`.)

Fixes: 1fe84fd4a402 ("kcsan: Add test suite")
Reported-by: Nathan Chancellor <nathan@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/Makefile | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index 8cf70f068d92..a45f3dfc8d14 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -16,6 +16,6 @@ obj-y := core.o debugfs.o report.o
 KCSAN_INSTRUMENT_BARRIERS_selftest.o := y
 obj-$(CONFIG_KCSAN_SELFTEST) += selftest.o
 
-CFLAGS_kcsan_test.o := $(CFLAGS_KCSAN) -g -fno-omit-frame-pointer
+CFLAGS_kcsan_test.o := $(CFLAGS_KCSAN) -fno-omit-frame-pointer
 CFLAGS_kcsan_test.o += $(DISABLE_STRUCTLEAK_PLUGIN)
 obj-$(CONFIG_KCSAN_KUNIT_TEST) += kcsan_test.o
-- 
2.40.0.rc1.284.g88254d51c5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230316224705.709984-2-elver%40google.com.
