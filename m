Return-Path: <kasan-dev+bncBCF5XGNWYQBRBRPW73YAKGQE4SRWMUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3c.google.com (mail-yw1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B5E4A13D16F
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 02:24:22 +0100 (CET)
Received: by mail-yw1-xc3c.google.com with SMTP id j9sf21264145ywg.14
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 17:24:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579137861; cv=pass;
        d=google.com; s=arc-20160816;
        b=ztbM+mjvyPsn+Y7RFloaLmpgLz4vJ8KR4nH5RraBEBny5kdCsgTklWZK6KOp/5fYDA
         CAnrulz7/YCEo8mIU1bSKHTUACBwOoVz5j7tusq3d0Nz+Kwbh9gNyuoZoX4S+HDvjICw
         42dDEALTzJlIIyYLkdpj4I3LE6sARXNRLWnlXDUacvxdChWutLAB/MEiqQE8jKGTPWq+
         fj+Vb4kkWmpKR2gsD7IudJ+0xidFkxluWnnrkiNC15d9dIVurmvBMchd/FoF/EI+mE4h
         dXWDMwIkBga5cHQxsQhhP++RD/327Ws/ocnZ4dUYfJ2jEbm88qq0wPfaNrNXHT/9eB9D
         frlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=WSqNJEx1RfXl8+uv6pn4kaWl3JI+mM8Pt25FrC6MhQc=;
        b=CVXTMGgL7k4ZCdLMvyUMKeofbdlXMo2vxjOkvO5tHphyMkQ/c2a2IAnzuCwb0Adqiv
         P5lqFimCpo3EBRHAyhqvjqDJeTKvJSW8kIP94l6rT1BrNKYthqu/maPohqo9FwRAq/y3
         5QuK0Y6PAKIchGLDaPEyVWHm7ZGDKnT/5PGqJ5f+kgDNN5nPjHFqybGH/2U7GkMj4YGi
         +GqPPOxTte/OZtztbk2wPRvRFnQkpQuv6fWfmb3LgmGc/6TTokpVFTCfXpT7Ecrwil6X
         A6a0xXMz3itlfsSdYrNzdft+kxCzj2OhI9ujx8fGe+q9yHs9ZgPls1lQ2wjvTGCKiPGi
         h7YQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Necsxt4U;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WSqNJEx1RfXl8+uv6pn4kaWl3JI+mM8Pt25FrC6MhQc=;
        b=iTBUiPsxzBfZsPHGWUqqYiAvuItWCQQEgfqm826dBKMlyY8T+fuVYjrv4ytb/coIan
         eXrXg2icKEwQkjytWs23my3IMc8+xlM8ESt0DRaJ4AyEsUWoip8YRUFqSAAyoSCULhCS
         Bm6NMlJg6/ea5+QhTs4n2IAOQ6eRA3tU+bKEuXon8G4V3v1Xiiyqlg3gjeNZSA07jPg0
         /ydCG2vZ8uk2LA5HdSGjPLAnL+LuSlfJOJzZ5yEqEq+XQpthY/bk3lY9OctwaqeYD7Yd
         a97I7PRwRg0izwMMNkj7/LASqk0IBmIjN9fP8uzsDAfLCUSLDnuL2B6fKCH7bVjTAy9W
         jsyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WSqNJEx1RfXl8+uv6pn4kaWl3JI+mM8Pt25FrC6MhQc=;
        b=chTnz3JyRwI/3j6GLK/n0rQ/AvVgc9bFcMaDwIJu/WGaWeUW7FEkAbgC1usaQMOsG1
         v/UTuNBrL7dgbjIzBWOi8e6MNyGDEnKwG7oSOPjasQcQivS23lWqRoFQiuOX6ew+LayW
         nRfCxsPpG86R6mbdqE4in6N8sSC4s/SDtc2YYtbRGURlruOiLrXEZTgFO/xUXTZwSlcK
         AHwslIESSSsfONFR7z4rDcvEpBJ1wd06T0JnFK9kN+HsVooi1zSCijmjkI0lqaFPkWHp
         tcBEouut059jR9bnkNfnultlJi3BPiAC1rt/y/gMkyL9lsXvyIT8CsJz1U426yKo1crb
         /iPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXToiwNdKCmo0i45S4zs4xaUzdAsF0Fl2ps98eAx61yl2QctQK+
	pAW7OvV7tNW656y3jreXHhA=
X-Google-Smtp-Source: APXvYqxVnqFkLTWvUZfFTxiCR+Uhw//YOauFOF7MPbcHdrgF8wkReYWOcuMQM6gS5Zq5V9WSEj7Z5Q==
X-Received: by 2002:a81:b548:: with SMTP id c8mr23421696ywk.465.1579137861765;
        Wed, 15 Jan 2020 17:24:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:194b:: with SMTP id 72ls3310002ywz.6.gmail; Wed, 15 Jan
 2020 17:24:21 -0800 (PST)
X-Received: by 2002:a81:2e43:: with SMTP id u64mr20320160ywu.488.1579137861313;
        Wed, 15 Jan 2020 17:24:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579137861; cv=none;
        d=google.com; s=arc-20160816;
        b=XbMyEGBnNubIl1lUAywvwxduDyJtey5gGODQwKOlYfiyqX9RTpj5zlI/HubyeARtwF
         DzzocAD/YCPMZVoruQbHSeaDHcayEbB1+RU5mArb2E9fX6SSz1H/ZeQlbemvSujslKH7
         70C/G9F1ghLCpUm4kRaIjn/NRt2sM5GQ+VHbaDs/97P4MRB3tu3i+7CpmLiOdm3SCGS+
         sAcjW27N34RVYvf+P3ylSgTqQgkoygEWrt7pKJWwlmCIXkgbwEWFbdQo+fdxhQH7NoU4
         M3OKc9ZTPUHIyxeepbBSxvSgLosFaqzmpvgoBFt1urhGZ6YO/6QxKLXzRN2EYoJX7fYd
         Bvww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ztBntqcbRDpikloUpN2F0KWZjGouqnztxdMWfXHrneU=;
        b=W71qpI8omqlQ9JFZjTbQsb/bUBHS+ppB2PNi1YMx7zYV9RDRmBsBJ6lQvX63m3+Ma8
         SMl8S45vTALz8hRPyDplj6lYUJOKOxtS8Nvr4XZYY9tBuMahNrECQ+g9oc1Jl2tSMfZ2
         6Qr3ayf9zVrFrC51NYrSPUtN7pCnPTVQvxmdbhr3RInCggJOajSiHmgDPUnW7RaLW8TB
         Xt7GQVgXNNU3HaEUbF8vJqqG97UkxAkmZH5VTnvx/Wy7NWIf1qhZDGbUep95Ak/BgOG/
         VKMsfx31mfsmjeOjYfCxa8XCEaqOdmmaJhu7UMESimzSk/8WS9F123L0LhanXY83H3+B
         NJow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Necsxt4U;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id s131si363318ybc.0.2020.01.15.17.24.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 17:24:21 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id s64so9036326pgb.9
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 17:24:21 -0800 (PST)
X-Received: by 2002:a63:7843:: with SMTP id t64mr36298336pgc.144.1579137860501;
        Wed, 15 Jan 2020 17:24:20 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id 144sm24408406pfc.124.2020.01.15.17.24.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2020 17:24:18 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com,
	syzkaller@googlegroups.com
Subject: [PATCH v3 0/6] ubsan: Split out bounds checker
Date: Wed, 15 Jan 2020 17:23:15 -0800
Message-Id: <20200116012321.26254-1-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Necsxt4U;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::544
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

This splits out the bounds checker so it can be individually used. This
is expected to be enabled in Android and hopefully for syzbot. Includes
LKDTM tests for behavioral corner-cases (beyond just the bounds checker),
and adjusts ubsan and kasan slightly for correct panic handling.

-Kees

v3:
 - use UBSAN menuconfig (will)
 - clean up ubsan report titles (dvyukov)
 - fix ubsan/kasan "panic" handling
 - add Acks
v2: https://lore.kernel.org/lkml/20191121181519.28637-1-keescook@chromium.org
v1: https://lore.kernel.org/lkml/20191120010636.27368-1-keescook@chromium.org


Kees Cook (6):
  ubsan: Add trap instrumentation option
  ubsan: Split "bounds" checker from other options
  lkdtm/bugs: Add arithmetic overflow and array bounds checks
  ubsan: Check panic_on_warn
  kasan: Unset panic_on_warn before calling panic()
  ubsan: Include bug type in report header

 drivers/misc/lkdtm/bugs.c  | 75 ++++++++++++++++++++++++++++++++++++++
 drivers/misc/lkdtm/core.c  |  3 ++
 drivers/misc/lkdtm/lkdtm.h |  3 ++
 lib/Kconfig.ubsan          | 49 +++++++++++++++++++++----
 lib/Makefile               |  2 +
 lib/ubsan.c                | 47 +++++++++++++-----------
 mm/kasan/report.c          | 10 ++++-
 scripts/Makefile.ubsan     | 16 ++++++--
 8 files changed, 172 insertions(+), 33 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200116012321.26254-1-keescook%40chromium.org.
