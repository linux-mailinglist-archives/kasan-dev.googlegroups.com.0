Return-Path: <kasan-dev+bncBCXO5E6EQQFBBWPN4KRQMGQEW6MG26I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id B0F8D71A250
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Jun 2023 17:18:50 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-33b0be9356bsf802195ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Jun 2023 08:18:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685632729; cv=pass;
        d=google.com; s=arc-20160816;
        b=pmkprx5c3M9z3sXibccj80zIYvRwVEgy37W2HdcsJ3FocMDtGAfZiZQheQEzWPqQJ4
         HFurq9erA0Gk0SJcc6RjlkvHytBMjNknXPM0n/Z9mSfYgLD/xowrCPW4AUU6afXcLx9u
         /oluwADiSziQL73PksVfL4ixWp9i3XM1kiHEWAqUT6T2o/BpgQ1z7qnje52qQcqayjsB
         vnmtg4We6mtdxaoxTehJ+LGox+YkHzsGuPtOqROmyyd+D0PNJKdKbwRTdGL8F+Z4RSz4
         4um/WEf9rdo3pFdTK3GG90NaWMLDJQb67A8XqyMj9bL28CS/eq612lOTS2Pxs+GgU5Hi
         6hMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=hGkJhOLxg6XliXmZmejKrFIUdUGGKjnz2LIz0lJ+GME=;
        b=IOE4tFiuJj/uqNDqEdIXlfE7wMgeFG/0aoaJlGcRFkhKnJf9KSJaywJP/LlMYSa3EV
         7EuoTwrq4c4a8eC7kWluZSObsMPjQplhxHg3FSvSxuZF5xkRakz7lkT4RcxBU9BGuy7U
         +U3VbVAs9i+Aq8VRM+9ShTQ0vTuJG5rrCT1liyIwYaFsXnc1NveXfgORmrF/aNYzoOIr
         B2C0OYJUFVL6RMseXF9BzJiVNoLiWhK6/N5aQ9FTeAO/2Dd/oYrs6l02YvI1ScMqQ1oc
         0jsdvKw7hQzY2nlHh0JTK7zm8aXfU0X7bvB/arcHLWE4Az4ODvcNcEH0EyIajuK9DfxK
         sD9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lOsYcDeZ;
       spf=pass (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685632729; x=1688224729;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=hGkJhOLxg6XliXmZmejKrFIUdUGGKjnz2LIz0lJ+GME=;
        b=D58ptJTDFAqKLiTs1sn8EZsOdokQyPglEZ7gdHXDZoMfFrKh8nbVWTemtszq9QumJi
         lBBjvh3fDjQLy/XcLV8Nvv4Nzo5lY7xhaVZ1YEutawqTJHqgBHvoMlRkqO3HS2QJHeSj
         xCQ9NZ1jmcuHZCCFqbfxNOectMBiXox9GFW2nCzZj9eHzDuFFjShKgIk0ox14PinKyfj
         WdJIkBozEbCFP0FXbq6Uv0KKhZQN2MZQZP8zRZOPN0CFLaP291PKSua4wxGnnReTiNtW
         /nzxa/Whx0mvDeJ8ez85DD4qQvClc+wK2SDwwBnpLYCVW/a7QG/7zce0HDTsRXJ+q25b
         Ysrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685632729; x=1688224729;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=hGkJhOLxg6XliXmZmejKrFIUdUGGKjnz2LIz0lJ+GME=;
        b=UrX4Yt+EV068/NEJXMFuzKiIDbgtjnsLSPnAzSgGpDPfbm2z5Qg4lNG/no4XYgCU3S
         TxzgscouLb6qh32lvD2BhbNjmDjBXQfNP2g71UjUgXNjsvljaTzMie7+k/brWvIDqXVF
         DGT3xQW4rXRyDu/ysDQSzP6DvedHfnBeBadL24mP7eEhjCDiypuPplGowNAfKa0+mOXC
         MTkIHsB+mJOWSL80/PbD0bG2kLodQxip0iNbbXGLXjWAuB2ZcJ+E2S+5BDSua8UC0qE0
         YPNjvKsaGWHjfIYB01LYZo+9YDc+QR7r55DTZCP8s6sSpCgOfHlU6YPeEdwMNJy7ohqU
         bDvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzeSvUjvIK+rvm6IKTa5jg/UfbAfc/pcgI2jmceAGIsYcJaceJN
	G0X3BZrsCxW9DgH8K3o0MKc=
X-Google-Smtp-Source: ACHHUZ78IepH3kUE1eUIyd79DiKW6BDSc9S4a5AIQEmfW4rIS7w1bAMyyffp/WZfrhg0fXdrXxLsrw==
X-Received: by 2002:a05:6e02:1ba7:b0:338:1993:1194 with SMTP id n7-20020a056e021ba700b0033819931194mr233621ili.2.1685632729406;
        Thu, 01 Jun 2023 08:18:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:eea:b0:336:1c16:1cd2 with SMTP id
 j10-20020a056e020eea00b003361c161cd2ls1048175ilk.0.-pod-prod-03-us; Thu, 01
 Jun 2023 08:18:48 -0700 (PDT)
X-Received: by 2002:a05:6602:2192:b0:770:28ee:fee1 with SMTP id b18-20020a056602219200b0077028eefee1mr6718324iob.7.1685632728792;
        Thu, 01 Jun 2023 08:18:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685632728; cv=none;
        d=google.com; s=arc-20160816;
        b=g7KQBstqfmfl8atj8Exn63gVQKPEoCUQhF/oikCdcye15587uDYHFd8DMhhbC7a3wc
         GADSGuWi3F60Uf+KT1NtQ58ZjOP2cje1TMwIZGZ4yj1r1N/VumO5058dm/dkNhHzxQF8
         07kAIbEXC403cgpr4IW81BNMClsxLrWGuInXUduOpMETDQD8i4Jx+pQuDTEGZOz0IXQz
         JaXb8FOpP8cfiQR9zU16SoCic7xejSbDeQoJZuG9QYOjIHetnTJ5zl9mOUC6x+PE5bVC
         hbXwvXE0Dz7fdc07RAtv3GyFbeq04dfq8+nlbOOxRXQM5LkxG2yg1uUR7vBEWe0jvqxC
         4Gnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=om6vVqhUTGRoMD24byuluNyuAPSz+SZ7EzIEE6u+Ouk=;
        b=EHAAoSnnWY6M3A/E9RwQ4xSYKf6w1sT3jTO1Kc2qRDQ+cQ/4G+KNjIrB4ZwWKHUytO
         HBq7WqVvvIbEVC683bT55rl5wtA7J+ILwStzqiOMl780RPbMMMa4KFN+fzIgdAy9TmQD
         g8A5Dn1yXkR6hMYKC3FIdQ3kDne+67+v0LcsBBKmeanhZOgDLPCKhir7nCffiPRv/gIu
         7rDzmVCeB7/82pHwmjVw0GT8HjNSQGvgBdfWzRBb/aOORc7Ir9OSeWLOptUJPPjtiwXT
         9caH2/Fo9YjUPY5p2093mT/uKAIhWBjPcDT6mv8nJTvQbQRF7ErA/yuXmywOLNmK8FAr
         3/Fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lOsYcDeZ;
       spf=pass (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 26-20020a0566380a5a00b0040fa7700d64si859832jap.4.2023.06.01.08.18.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Jun 2023 08:18:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 5FC866468C;
	Thu,  1 Jun 2023 15:18:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C525FC4339C;
	Thu,  1 Jun 2023 15:18:42 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: kasan-dev@googlegroups.com,
	ryabinin.a.a@gmail.com
Cc: glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	elver@google.com,
	linux-media@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	herbert@gondor.apana.org.au,
	ardb@kernel.org,
	mchehab@kernel.org,
	Arnd Bergmann <arnd@arndb.de>,
	Dan Carpenter <dan.carpenter@linaro.org>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Tom Rix <trix@redhat.com>,
	Kees Cook <keescook@chromium.org>,
	Josh Poimboeuf <jpoimboe@kernel.org>,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-mediatek@lists.infradead.org,
	llvm@lists.linux.dev
Subject: [PATCH] [RFC] ubsan: disallow bounds checking with gcov on broken gcc
Date: Thu,  1 Jun 2023 17:18:11 +0200
Message-Id: <20230601151832.3632525-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lOsYcDeZ;       spf=pass
 (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Arnd Bergmann <arnd@arndb.de>

Combining UBSAN and GCOV in randconfig builds results in a number of
stack frame size warnings, such as:

crypto/twofish_common.c:683:1: error: the frame size of 2040 bytes is larger than 1024 bytes [-Werror=frame-larger-than=]
drivers/media/platform/mediatek/vcodec/vdec/vdec_vp9_req_lat_if.c:1589:1: error: the frame size of 1696 bytes is larger than 1400 bytes [-Werror=frame-larger-than=]
drivers/media/platform/verisilicon/hantro_g2_vp9_dec.c:754:1: error: the frame size of 1260 bytes is larger than 1024 bytes [-Werror=frame-larger-than=]
drivers/staging/media/ipu3/ipu3-css-params.c:1206:1: error: the frame size of 1080 bytes is larger than 1024 bytes [-Werror=frame-larger-than=]
drivers/staging/media/rkvdec/rkvdec-vp9.c:1042:1: error: the frame size of 2176 bytes is larger than 2048 bytes [-Werror=frame-larger-than=]
drivers/staging/media/rkvdec/rkvdec-vp9.c:995:1: error: the frame size of 1656 bytes is larger than 1024 bytes [-Werror=frame-larger-than=]

I managed to track this down to the -fsanitize=bounds option clashing
with the -fprofile-arcs option, which leads a lot of spilled temporary
variables in generated instrumentation code.

Hopefully this can be addressed in future gcc releases the same way
that clang handles the combination, but for existing compiler releases,
it seems best to disable one of the two flags. This can be done either
globally by just not passing both at the same time, or locally using
the no_sanitize or no_instrument_function attributes in the affected
functions.

Try the simplest approach here, and turn off -fsanitize=bounds on
gcc when GCOV is enabled, leaving the rest of UBSAN working. Doing
this globally also helps avoid inefficient code from the same
problem that did not push the build over the warning limit.

Reported-by: Dan Carpenter <dan.carpenter@linaro.org>
Link: https://lore.kernel.org/stable/6b1a0ee6-c78b-4873-bfd5-89798fce9899@kili.mountain/
Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110074
Link: https://godbolt.org/z/zvf7YqK5K
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 lib/Kconfig.ubsan | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index f7cbbad2bb2f4..8f71ff8f27576 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -29,6 +29,8 @@ config UBSAN_TRAP
 
 config CC_HAS_UBSAN_BOUNDS_STRICT
 	def_bool $(cc-option,-fsanitize=bounds-strict)
+	# work around https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110074
+	depends on GCC_VERSION > 140000 || !GCOV_PROFILE_ALL
 	help
 	  The -fsanitize=bounds-strict option is only available on GCC,
 	  but uses the more strict handling of arrays that includes knowledge
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230601151832.3632525-1-arnd%40kernel.org.
