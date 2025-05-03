Return-Path: <kasan-dev+bncBDCPL7WX3MKBBBGJ3HAAMGQE6PSAGBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E788AA81F5
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 20:46:30 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-e6e40ff0874sf4387495276.2
        for <lists+kasan-dev@lfdr.de>; Sat, 03 May 2025 11:46:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746297989; cv=pass;
        d=google.com; s=arc-20240605;
        b=Dcu+VPNTLjbDBDJXk2x8da/6BN7vG10mg4TYk/F7zIVA49o/zh9f3bUh51TJbmrAgK
         TtmmuZVqcu8utAxY6LLC4T6NOFcCiQXNc3keFazVPYyvLScHfO4iC6rEpYu0mixtK27K
         ydDUu+2702f4s9HxisYHqtcrT9w7tvOrLemlQsOFOXJTSkBC4I/4Bg3q+li2volxVK/B
         h2aaWlq57nYBXpgBe9TQ4X25jpKWKNH2yjXzhRooXMxb7Uq+WRnRhRyn2biWIPQ6aV6X
         FihK/03YywDjsieYo6oYbweoEDQKdcrDK7VcS3AqjwVdpZSkIW/Y0d5DZbW6tw1NuMzR
         LXlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=xyth8Tu9fPIpufKa2IgLyNGS1+BlZfGBvnQ+GeX7e1s=;
        fh=72uYqZxf/W+C9PVcnTmMIq+5sdadTLr2jugLoXYD5Hk=;
        b=QlUcYhSWFwQsfbEVhcfkOFJXijfXcyX3ExmMgMgGD508W6i5zO/ho1U+WOVZpsrtC6
         dM3+dMHt1vuBPpv1o7UPJbFulO7jokUz21We+bsAh2/efvXQA6P88lN0xtbUeKC8T0m7
         c4mvFXY8npDr1ogKRFqmHRsC+yFHiz++8W6Ti/q3XrzOiavnmMfi15Pt/YFnoSn/D7Xi
         HlE+46zqu5GT6hSvtKZNrXe0tc12PtyulXeJm+4v9lM8CCXcYJL2RN3l8fWSnnAeP60Q
         MGBFC3m3y1ejeN2LNe+wqkT2NnISuuYnw0anjlG/wMjwl4Ba3RRxhvLwhvF/zRJspG5p
         4vag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="HX/h4kW+";
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746297989; x=1746902789; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xyth8Tu9fPIpufKa2IgLyNGS1+BlZfGBvnQ+GeX7e1s=;
        b=NANRp3lKsjJCOCVkG4W74wD+UBQlho7KxqqgMNn5MeUAtbFiWruhV+IVp8GmhVLIN0
         Y5lRNBSwfgoo8ATzPYoj10A847Y7zhHclVjHXgB9LzfZrtWzUqb3cTjpQ+Q3URUuouyB
         cXxTpc+W4VsfsBOJfl5dxyxnC8dOn5uuP6g3wQylGT5DvUdafgN73wExTCfGjhwl1mHM
         h4L21TFW6ac/X4TdbZ6xS3urnzuQ3xnaueyRYvWk5ZmQ6AGL70fJ3/Nfw9PLZYW/QG8O
         S8vYnxejWngXnRjlEScecWdb9XdnuKWJlPlbxOM6zn1I2Fj+QXu4PBQ3xiWwwa1jf4gR
         CZAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746297989; x=1746902789;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xyth8Tu9fPIpufKa2IgLyNGS1+BlZfGBvnQ+GeX7e1s=;
        b=UqwaP2AckbfOzdGgY0fN4HT3HdPofACmLOCdvFfp5Oil9RS0P6G3EFsxkAw9PKN9Zq
         L1GYQh86jfmlrOKG/pQt7XPyNbg+4xWyOu1dtfSJsBzJ4HSc9aUDyNdZVAo0OfsT/8wW
         LjvBdM0Z0CLOq6HvtdkCae56QEDCxoJwinAija7gdflW9HHl8ehyrkJ55zN3Nc19vX/y
         OVILOBQgJ54HJuB1Nv9jyJUHjIc/LQw68ZgFdhKJUAojFcHEbqygjKW9Fq3sSFU7h9N5
         2+e6+xpABHzUbG97i3i4YxsaOLoptrYs5dIvVY6Lj+rc6I64W9txQlQFq5tLLG2wNwzE
         gkEg==
X-Forwarded-Encrypted: i=2; AJvYcCXf6VvAV1P6mjdYZtHMms3dX0jQeEs0+obdL4yG0ba13G+n0F0bHz817m91e4Ft485Ln9pXvQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy7FrU11YXoEEIBGOFqFlteI0peQVOzscvePa6zc5LR4KBOGDJQ
	MEUdT4CT6lmaQ1JQI+gRYnNfsNpeyUECmGpKUgo6HdjHJygb5+qh
X-Google-Smtp-Source: AGHT+IFUfoN5aVXwxJWpyFzZunxxPLsD8GfFcSMymgjf7Ua/uWPed93Q3YIOdn2/uaXoRM0mnMLfEA==
X-Received: by 2002:a05:6902:230e:b0:e72:88fc:ca98 with SMTP id 3f1490d57ef6-e757d0e227amr2210055276.20.1746297988819;
        Sat, 03 May 2025 11:46:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHL5JZWaU29/cekkYjZALa0dHZIHiRKuw0nXPcmJpqqCg==
Received: by 2002:a25:2d20:0:b0:e60:873d:ae8f with SMTP id 3f1490d57ef6-e74dcaaf920ls328126276.2.-pod-prod-09-us;
 Sat, 03 May 2025 11:46:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWFBU4SdiqR/PWo3HpLfaCZSb3dRthjHab9RWg/KBul8AvazqERzRKOy2M23gOnrRmnKpZXXmkFDdI=@googlegroups.com
X-Received: by 2002:a05:6902:1004:b0:e6d:f6f8:69ed with SMTP id 3f1490d57ef6-e757d55701amr2165176276.48.1746297987724;
        Sat, 03 May 2025 11:46:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746297987; cv=none;
        d=google.com; s=arc-20240605;
        b=f6McMYDGxogGXQb7WXi5cKuRgIFREQInZhRWMWV1BVOthdhFPVwf5/s2P6XYMoYJu2
         hEXmM9rO3KxjUKfjO3/PQd1+k83RU6ScBb2N31sW5eW7szPcmW6X7uKxQxuwn76pOfS0
         WU25Is20bFEEs9K8/7+eZNyAetv+xWcgTd0QODoUiG7bvAXLQxtcV9T2bA8cGCI9JaN+
         MBUGrPb4rzBaXOs43SE4a6xs9MXo3HkVmZ4ZXnEw9PoKiMj/M7i2jXuk9EY23+BeLWwx
         bknihSozWrKBHseRqeI6kobSEbvSMOzTIbgPYErU/oW11qHEcnbI3K3d5lyvf8dcZIl1
         QwpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ibcMf2302Elhq/FRwTM4VNZTBA5cKxWVBjVVPjjbh30=;
        fh=a4zW9Gar//hW/Xg3mGEY44PGZpG6goovj1gq9JAXMOA=;
        b=KitI7XiVvNV+2+Xn0bzs3UpJnUOmhJp/PWBkTysXu01nuY1oL5JveedSd7To3rA2eR
         1X5jJDYXZTpOP4mvYBZH7dvsofQJ3LbhvtvTYL6M1pEA2/nAL5ZxFjcee8kddjW0+SXl
         o3xwuQO7nNQaCoc+w1ldCAETaau/WFyfGBnIkfvlGbX/HNRaftejU5R3axV5tWFR5m+i
         OJYzXTTpPIJKmnEPRM6JgZuHd3Wi9gO3UZ+SEefmJN06e7PUDVtJYQLRa3+JgHnqIDzj
         AkUAQPXuO1T5etu1pZRoN4EDdn86UiF/+rlQwToC19vizLiMqCksuXxBJVZHRf1YGCFz
         Q+MA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="HX/h4kW+";
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e755e790366si254419276.3.2025.05.03.11.46.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 03 May 2025 11:46:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 8698FA4051C;
	Sat,  3 May 2025 18:40:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 83E05C4AF0C;
	Sat,  3 May 2025 18:46:26 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Kees Cook <kees@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nathan Chancellor <nathan@kernel.org>,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	llvm@lists.linux.dev
Subject: [PATCH v3 0/3] Detect changed compiler dependencies for full rebuild
Date: Sat,  3 May 2025 11:46:17 -0700
Message-Id: <20250503184001.make.594-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2613; i=kees@kernel.org; h=from:subject:message-id; bh=cmrsue879i0SFR336+VtZOxozOZsiQ5dawHHXzQfCT4=; b=owGbwMvMwCVmps19z/KJym7G02pJDBliKex5Glf6uqY79um+fzhV7e/G6CI/q6v1Lx66z1du+ s798NWZjlIWBjEuBlkxRZYgO/c4F4+37eHucxVh5rAygQxh4OIUgInM72L4nxz345rV9LzVEx9G C8dp7Dd573ZI0O22kPspF4NEW7NvPxkZTh+XTkr8kxx4LV9zV9vpe5JsjydbFx5Njs65wCubOOc mCwA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="HX/h4kW+";       spf=pass
 (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

 v3: move to include/generated, add touch helper
 v2: https://lore.kernel.org/lkml/20250502224512.it.706-kees@kernel.org/
 v1: https://lore.kernel.org/lkml/20250501193839.work.525-kees@kernel.org/

Hi,

This is my attempt to introduce dependencies that track the various
compiler behaviors that may globally change the build that aren't
represented by either compiler flags nor the compiler version
(CC_VERSION_TEXT). Namely, this is to detect when the contents of a
file the compiler uses changes. We have 3 such situations currently in
the tree:

- If any of the GCC plugins change, we need to rebuild everything that
  was built with them, as they may have changed their behavior and those
  behaviors may need to be synchronized across all translation units.
  (The most obvious of these is the randstruct GCC plugin, but is true
  for most of them.)

- If the randstruct seed itself changes (whether for GCC plugins or
  Clang), the entire tree needs to be rebuilt since the randomization of
  structures may change between compilation units if not.

- If the integer-wrap-ignore.scl file for Clang's integer wrapping
  sanitizer changes, a full rebuild is needed as the coverage for wrapping
  types may have changed, once again cause behavior differences between
  compilation units.

The current solution is to:
- Touch a .h file in include/generated that is updated when the specific
  dependencies change.
  e.g.: randstruct_hash.h depends on randstruct.seed

- Add a conditional -D argument for each separate case
  e.g.: RANDSTRUCT_CFLAGS += -DRANDSTRUCT

- Include the .h file from compiler-version.h through an #ifdef for the define
  e.g.:
  #ifdef RANDSTUCT
  #include <generated/randstruct_hash.h>
  #endif

This means that all targets gain the dependency (via fixdep), but only
when the defines are active, which means they are trivially controlled
by the existing CFLAGS removal mechanisms that are already being used
to turn off each of the above features.

-Kees

Kees Cook (3):
  gcc-plugins: Force full rebuild when plugins change
  randstruct: Force full rebuild when seed changes
  integer-wrap: Force full rebuild when .scl file changes

 include/linux/compiler-version.h | 10 ++++++++++
 include/linux/vermagic.h         |  1 -
 scripts/Makefile.gcc-plugins     |  2 +-
 scripts/Makefile.lib             | 18 ++++++++++++++++++
 scripts/Makefile.ubsan           |  1 +
 scripts/basic/Makefile           |  5 +++++
 scripts/gcc-plugins/Makefile     |  4 ++++
 7 files changed, 39 insertions(+), 2 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250503184001.make.594-kees%40kernel.org.
