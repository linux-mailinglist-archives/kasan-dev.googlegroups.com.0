Return-Path: <kasan-dev+bncBCXO5E6EQQFBBBU64SQQMGQE6VOCGSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 58F4B6E1E44
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Apr 2023 10:30:00 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id h206-20020a2521d7000000b00b8f3681db1esf8671545ybh.11
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Apr 2023 01:30:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681460999; cv=pass;
        d=google.com; s=arc-20160816;
        b=xyhWgiwgygJY3q5qhnEXBJkzhAyFcZO8jmBJPO54qDhwBxzIx2sH7wNQFiaOqVdbw9
         3NNIkwJ3LmZV4C/bu1AAbrivkJ60d8UqlZ90tgNCkYtQPy5wz1/MvVSDeoLErWtBkU+g
         YPLvXWx+xveaPvPTlf/jOz/uFG/be3ZtlHeTHpkoyRsxh/ocem4gELBzEKKZDBSgvFQA
         bsFBfQwxzQwGaryn3lc3mtVkpjACtHidX9zW9bco4CGltKhkBWzPLAOCnoM6KecUZKcB
         smMKCxgamyJOQBEoVc2Pg4RCLxv8L4KqMmfe+QUHWDF0jeEfyB13TfQftPh7Tk+H+BJF
         7lsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=fyJGcmgRqBipuKVXTqHAGPsqShq2dUEoPrijIB4PojE=;
        b=sQSDYGzqHMzJVcPxDwEPOQMcGCQx2SUwnYolcHpswHNvnY7iqW9HcaaKGDmdTMtazH
         PmhTasFefQ0TgtVuXIeBSifJPKahtyrZVnOv4YcjlNt6kRvsfgLFprEhnG/hy8XBXhBT
         wCTh+bZjRHd7DTvMkIm1rYn0yqLEPb9ZRYkVud6Mc8J8DyTe+8Pvr0qS/lGysgLwYfoA
         6xs+bvz/HVAGwHELBsJ5fJleBVdoGbqTQ3NIU0sra2DY5tIho2PFAb679Uvd30ktsxYS
         srg2t+N172MWwegS0CXDGHjoofd+FsdAux+w/gPAI91rr+nOHjmYRwf0sWvO8ohAo8Zb
         7xBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MAc0Wdvt;
       spf=pass (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681460999; x=1684052999;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fyJGcmgRqBipuKVXTqHAGPsqShq2dUEoPrijIB4PojE=;
        b=M1IMHlJInlGIRgu+pyjkEoZLmlSlG8+bGd5NgIJlQmCNgKarBQKIUL4ETBmuDLHL10
         N0Fjtusiwob+6uNCkZrJfhUbMRzyXm/IdHoWowC8NPD6AibV7pVJUfVrPS1Il9c3Al+R
         BHBe2LMV6qmVpTLfz8IAY8NdbiUSZEhKmr4iwkpQooOuDom2Y7ybiBUhoLYkc+mw3S6f
         ySBk35nHj6ru9OrsuYcQWtBbgQTqTOIuSMInMr4+e78j61zwpnJ387fgHWWsMLIwoFt4
         9o0ufKun3Xciw9aEEhKf4EsPJMPUjOwciu1+vFZbDK4I6qEXBE3v9xBl8UdKm0OrO0Vm
         1DgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681460999; x=1684052999;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fyJGcmgRqBipuKVXTqHAGPsqShq2dUEoPrijIB4PojE=;
        b=DBFjn2WTKT/yCngY+ic8qsQPRBTpP3xHGyZP8AMqvhL8doEgKVH+jO6E7WTb9+Wl0q
         tcGKqVVaYrxDVfaELmx+DqTfWTPjh9EklEjVpqfYh9/r44THlvfzcTRFiZWOMnPv1fk3
         x5rHX9t1RSUaJkB0txu2+JrEV88badz+VX76RGGzB2tKyWvCiwwLEDibTSWDBWfuz4x7
         2kSK6A6G7boUodFnnkcKjdrWSOI9hPL6h5J1HD2ADF2cadfNNAfwBgHl9ff1qoB3nhDQ
         HrxyP9zGBXTCbAeZEYivWGPBJCNMqGVcC4CeQUaBf/DWyGgZ0PDDjiKyFLm8Qlfe2rke
         YK9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9civgKnQgY5d/XL38K8OK8fwm7d26uqUrQaONq+e1ouEQv1EhaX
	z9JwYwyE2f6u25EXzpufg/Y=
X-Google-Smtp-Source: AKy350bnh69Yp24MxzXmlrpXy73wnKCoec+nBOyEqu50H7XoEgLCIKs1HlAK8LR+CdsAaQp2CwBjdg==
X-Received: by 2002:a81:4319:0:b0:545:62cb:3bcf with SMTP id q25-20020a814319000000b0054562cb3bcfmr3217576ywa.2.1681460998980;
        Fri, 14 Apr 2023 01:29:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:784b:0:b0:54f:6fc7:90a8 with SMTP id t72-20020a81784b000000b0054f6fc790a8ls6654351ywc.9.-pod-prod-gmail;
 Fri, 14 Apr 2023 01:29:58 -0700 (PDT)
X-Received: by 2002:a81:928e:0:b0:54c:27e7:b1fd with SMTP id j136-20020a81928e000000b0054c27e7b1fdmr4650141ywg.37.1681460998344;
        Fri, 14 Apr 2023 01:29:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681460998; cv=none;
        d=google.com; s=arc-20160816;
        b=dnYr36DkVvgSm2HHwH4/EMeOjWjryHRapD7Ydzi1venfiF7QmBUP3jNR/Xmn9WBVW3
         NRYKLl7JBpVo8fpaqvDPH6KfLoHmffyAwVgPBz/Q93VLuvwamsmCs7oVX6Diq8iVoKbB
         X7FqB+ygUGqAH8keJmoWPvfGe/e07M3pyoDn1qRuq194PypNbEty4hFrGoTOhDStGzkr
         /nGo71kiSizXeNGApoBdl/9fGXdsqEba8eK9Uh5TlFrx01jsX5OY4r/5jnDsbpayDO1D
         VauL/wzWIlkvRHTvrfIhZG/+bhj4Jkt2hucZ/rfk6mXsIhrjKzEzfloUPuLjEd3/bWqr
         l4Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=F0nAr7knvbuggdLaOyKz0wqlPkbknidAEagf8h7aml4=;
        b=zcTz8OSt4A3GyR4WqZkIKcb0MLnyqUmWL7W2pn2OE0rwxPAraH0+Coc7Ty31nIni0g
         uIsKeQOBRSG3onKJYcvK6f+0tWxDTBX/f6174CSvR959Kwu83+FsenLyezstWqbzW6RZ
         9+Wv08oUrRVPixfwFA/h1GR56Ns50AJKSiZL4n+Eza/NWtT12wHJRNJ1WpkPnWSuYNAo
         CUerdeHWwHJyOTbbi7maOI0wSbASBtGetu2iG5qiyodoCqf3PxEey3FCp+6+sDSZrI4j
         Y735ucKpYPKr61lINJa+p9IMwXWiU2yCSf9et5vVO8ia0SaAgX+TYmt7PHOOd9GjfvM9
         Vu5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MAc0Wdvt;
       spf=pass (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id cm2-20020a05690c0c8200b0054f8076205fsi184944ywb.1.2023.04.14.01.29.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 Apr 2023 01:29:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id F263864541;
	Fri, 14 Apr 2023 08:29:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 48916C433EF;
	Fri, 14 Apr 2023 08:29:53 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Tom Rix <trix@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH] kasan: remove hwasan-kernel-mem-intrinsic-prefix=1 for clang-14
Date: Fri, 14 Apr 2023 10:29:27 +0200
Message-Id: <20230414082943.1341757-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MAc0Wdvt;       spf=pass
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

Unknown -mllvm options don't cause an error to be returned by clang, so
the cc-option helper adds the unknown hwasan-kernel-mem-intrinsic-prefix=1
flag to CFLAGS with compilers that are new enough for hwasan but too
old for this option. This causes a rather unreadable build failure:

fixdep: error opening file: scripts/mod/.empty.o.d: No such file or directory
make[4]: *** [/home/arnd/arm-soc/scripts/Makefile.build:252: scripts/mod/empty.o] Error 2
fixdep: error opening file: scripts/mod/.devicetable-offsets.s.d: No such file or directory
make[4]: *** [/home/arnd/arm-soc/scripts/Makefile.build:114: scripts/mod/devicetable-offsets.s] Error 2

Add a version check to only allow this option with clang-15, gcc-13
or later versions.

Fixes: 51287dcb00cc ("kasan: emit different calls for instrumentable memintrinsics")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
There is probably a better way to do this than to add version checks,
but I could not figure it out.
---
 scripts/Makefile.kasan | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index c186110ffa20..2cea0592e343 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -69,7 +69,12 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
 		$(instrumentation_flags)
 
 # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
+ifeq ($(call clang-min-version, 150000),y)
 CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
+endif
+ifeq ($(call gcc-min-version, 130000),y)
+CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
+endif
 
 endif # CONFIG_KASAN_SW_TAGS
 
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230414082943.1341757-1-arnd%40kernel.org.
