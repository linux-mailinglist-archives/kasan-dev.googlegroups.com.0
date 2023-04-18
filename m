Return-Path: <kasan-dev+bncBCXO5E6EQQFBBXUX7KQQMGQERZV6I3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A8FF6E612A
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 14:24:00 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-18486cd43d7sf3758019fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 05:24:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681820639; cv=pass;
        d=google.com; s=arc-20160816;
        b=KMUOQgmZIWYTy3K4Yw8bLmauIH8Uut6BfaNH5G/8ZL+LUX8QkJHrlCwzuHIxqY3Kke
         PVB6YLvEft232189Wd8lmWkNz2DF9js6Kuq2tMy55obMzbak18603Ss7hkNvgQ0/OG/u
         kcPNQEY4sX2sCnuph9VXayIWNyAUBUb20RTgS57DoBNHfP1DYZktqhH1GFsyhvX8hHH4
         4qlTXHUqGdVh+RM6awtw1XZ7Jn5YyZNZ/oQhpSJT+tbcoo9fhBbgsQGJIjcu2GlMgqq+
         n1M2d4JxR7eHjvtDf+dvdYGBOOuMzGwnp9wET9mCRNhMAMybrjBOw7zKb3DFrZ0dvs2h
         BL9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=bbPQzzwtQnpli9gV9nRfZRPzole5asTvZCePdqHVzxQ=;
        b=ep7exJBOQ/1NKnPBY56zX5FEoPvMUE1Q5/6Op50r/JxUsF+gdUl94ntdYahqUVUVoD
         +wAnDKEzgmmInIAazpfbW/i4cE/eT/BCnUO4gJHASswN1u7S57OUJwyv1WGKeiWFFHEj
         m2PJ9LAvgRxT/mekF57+m5LwO4UqzgdUriaohU3nsbrWJrFbx8Y4t61pOruG71WMzKTw
         I7qIM/sfpWrBE2D1QUKajGP+7DVcVwaY9cqiFJfD0fXRrFy2RezJmbTWl5JEm1dvWQSp
         VC6dvtznMY9T3NrYmbQ9Pug18IQgjInHtu8R3ci0yxFeDWCvSNnqX6Wh14144ytZOiKV
         1nhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZV5ApDRA;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681820639; x=1684412639;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bbPQzzwtQnpli9gV9nRfZRPzole5asTvZCePdqHVzxQ=;
        b=KHqczqVEiYJJnOeIxZtPk+Un8jUd+1GsEQnd0o4DwREVEXIBu5gURVo5RQVE6eTiL6
         9IqxMZg3u+RHc73wZrCwRx+0/77ZrWDRldEu8maU1lNalfqlOB3s6oRg49LYKBxDbFre
         LMMoW6HJfojo79dGPKHJ1oZSQvyBNOMsWKd1wYHU4ofFVEuv/8we3qBWw01cxQFuuRuz
         1R5jEsWeCEwZRPUphbrzLcnLKJ5Fw4dQvasjnd4NO8fQKbPz4NdP+E2tKM4O+QLu/x99
         iXBzJd11cbouK1Ur/3nLxvDTmzrQYgNeeGXiQXKSDlt/w0wvetzN/ZwNViE51OBBkLOC
         t04Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681820639; x=1684412639;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bbPQzzwtQnpli9gV9nRfZRPzole5asTvZCePdqHVzxQ=;
        b=dmFk+CgCEBF+EwQ5op7v+Pcqm99mtofzerc1pdWmJ4up/z+d1nBU7oYlHHqSUWKxGs
         xpoQI30O1MhHexxpGdH1p0sXbUI+lhtL3ZemMENmMaBW64FpyjjJutz2SRtWT4WmA57Y
         w0eyUBqmDzbzN0iHsdR1gW1sNahcY/o9jL7btLs4nvJpki72670o8RJbBaOe3QikOgSw
         +1jNVfVNHi+kOD4xR29AJoOj3OOEcITo5+RglV6damP9s4m/3wj/rB3K9/OsZ2UKuiSX
         7w2MpgTz9FvNp8FPUTG86I1df6vGNgjYevM+SfY0VRoKhVy5KqRod5zKT4TO08SfKp7Z
         SMdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9cwV6Z9P6UG26KgRFqgk0tN7qRm3uvWJMLcZrh9nnuWzpS5POvu
	Pev5qJtq7Q9hGsyTMN24bXE=
X-Google-Smtp-Source: AKy350YooylRjkwc/swZ8WqjwQ2i8OzyQ2/8BnO998ryXBOvBrgxAWK4hS9Zsy9DHmjVBTYiW1U2eQ==
X-Received: by 2002:a9d:7517:0:b0:6a5:fa81:3b66 with SMTP id r23-20020a9d7517000000b006a5fa813b66mr599484otk.0.1681820638943;
        Tue, 18 Apr 2023 05:23:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:2e2:0:b0:6a4:3d60:27b4 with SMTP id 89-20020a9d02e2000000b006a43d6027b4ls2071792otl.0.-pod-prod-gmail;
 Tue, 18 Apr 2023 05:23:58 -0700 (PDT)
X-Received: by 2002:a05:6830:1e78:b0:6a5:de65:9927 with SMTP id m24-20020a0568301e7800b006a5de659927mr1049129otr.11.1681820638441;
        Tue, 18 Apr 2023 05:23:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681820638; cv=none;
        d=google.com; s=arc-20160816;
        b=YgGiu5QRpBYEMNETtc9WbMhBezhmgtCGmjzi2xu3xyrqOL3bvmravjfOCqe/+09wvS
         eUb1IdLPR/T92pKHhg0/ODLnEi9sUpOQIFwPgfKPr0oW6/LpvOpNV6r8ncIxDLTP+j4e
         UWGT77Q4upIu4pBGa5+cPHdU+mNnQmo0nsAl2HmwIXkwx+4LbdhlO25y7nZaojMJ+vIh
         QJvQm/p0KBJYUPwm5TRiJtQNuWmjyK1a+m9LZDzgUSoSDkbgBOedHO55s4XnTIDWhNZF
         L3ynCM+IG8mhq5UyyAoXZxBSeNqvfbwJpFGtuK2Hla2zTQ1U3JpeSkqR07pyUISjK7UH
         tE2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=rCHsboCrzW2SygIqg56Vq9y+2W0XVFNSXAStqyqIoOo=;
        b=KIS+fUzF24g9WtjSLLHttEdTfezvnXP1J/OoFYsLqtyfP4nvaRhSj1qios3C6j9vHy
         JoWY1t4WvCXv0XTo80okQJiPP2MuPrgP7RMP4bylGlTG9nqnLmb2RmPsy8WoLkDpJ5jT
         AD+qv+kXyFTe5tJhGp0D8rKrB5uPqrPJ9XOqV3OOL8G/lyoc7PV6nGPu6OrtfAdNpcWo
         fSnosWuq2K1gwWW78b7haBrxnzVIltIacy1jhCOsa6lfhbISnBdWNScFyODVVlyNbmd3
         x8PYRq4UlTmymLMEBykVFvPlB9CQ7TU3iOSUbhq+7dux/EYhVL/L/I4WvVV0NZiqq+Bl
         lRwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZV5ApDRA;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ca8-20020a056830610800b006a15693a266si1516825otb.3.2023.04.18.05.23.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Apr 2023 05:23:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 40E8B614E5;
	Tue, 18 Apr 2023 12:23:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CA6D4C4339B;
	Tue, 18 Apr 2023 12:23:53 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Masahiro Yamada <masahiroy@kernel.org>,
	Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Tom Rix <trix@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH] [v2] kasan: remove hwasan-kernel-mem-intrinsic-prefix=1 for clang-14
Date: Tue, 18 Apr 2023 14:23:35 +0200
Message-Id: <20230418122350.1646391-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZV5ApDRA;       spf=pass
 (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

Some unknown -mllvm options (i.e. those starting with the letter "h")
don't cause an error to be returned by clang, so the cc-option helper
adds the unknown hwasan-kernel-mem-intrinsic-prefix=1 flag to CFLAGS
with compilers that are new enough for hwasan but too old for this option.

This causes a rather unreadable build failure:

fixdep: error opening file: scripts/mod/.empty.o.d: No such file or directory
make[4]: *** [/home/arnd/arm-soc/scripts/Makefile.build:252: scripts/mod/empty.o] Error 2
fixdep: error opening file: scripts/mod/.devicetable-offsets.s.d: No such file or directory
make[4]: *** [/home/arnd/arm-soc/scripts/Makefile.build:114: scripts/mod/devicetable-offsets.s] Error 2

Add a version check to only allow this option with clang-15, gcc-13
or later versions.

Fixes: 51287dcb00cc ("kasan: emit different calls for instrumentable memintrinsics")
Link: https://lore.kernel.org/all/CANpmjNMwYosrvqh4ogDO8rgn+SeDHM2b-shD21wTypm_6MMe=g@mail.gmail.com/
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
v2: use one-line version check for both clang and gcc, clarify changelog text
---
 scripts/Makefile.kasan | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index c186110ffa20..390658a2d5b7 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -69,7 +69,9 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
 		$(instrumentation_flags)
 
 # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
+ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
 CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
+endif
 
 endif # CONFIG_KASAN_SW_TAGS
 
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230418122350.1646391-1-arnd%40kernel.org.
