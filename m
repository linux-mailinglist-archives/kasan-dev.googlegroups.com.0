Return-Path: <kasan-dev+bncBD4NDKWHQYDRBVXQRKKAMGQEVFUTLLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id BC057529154
	for <lists+kasan-dev@lfdr.de>; Mon, 16 May 2022 22:47:20 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id h23-20020a17090a051700b001dc9132f2e6sf209040pjh.6
        for <lists+kasan-dev@lfdr.de>; Mon, 16 May 2022 13:47:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652734039; cv=pass;
        d=google.com; s=arc-20160816;
        b=i8bQRBdYEBY1StffNHnk1b/7Dn9o+nB3KWoSlH8YBu2CP5FuyImiSjpe2fYS3ne+wp
         /5hMEnSvBA1liUygQxHeshzHIFnd2/RbaX1ywVWagTns2/ZKFjig/RLxcplQ734KPGKS
         dJoj88frappM51CmiXiwN+bkYIm4iKUyzYYcMaHspQJyBmMqrhzbYWugTPEVlTTDhhwA
         BrQODJIj1cRYyjQlVpnO4GZugqRo3j79gyK44na/aVjY+6HwxJ2vnIo+cCddVykY8/F+
         Q8rkCO9q6GQ+Wh3APg/Qc2CesVaIH4fwHsN/hm1OFA0m3rTi9OsLkhfBbjdR4B4oHISr
         Fbog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=CUfD6ZWofScSR3zLBPL1W6ZHUau7G95UmAsedPjK2Cc=;
        b=Ud3QBDrax2FXeGAmbkW1mrr37yOTw+dde89oJ1Tjceh3ACWrNcl9aPTSApbLtcYBXd
         WiA7tDzER0uKkhJCiy9vPLOq19Rgndajve6OtjDYnteveKIBDggEgStyaUKaxeV6LOM/
         F4kYEc/BbK1LBx8erK4HVSu8TEphOMPNno+ZgEsvWibd40Ms1Jjlu8zDg68KbOTe3Fyw
         Yegfrdbp7QQYV8vkhX/AYGogi/L59O9K7e2Yoj2gt1GHXdRX2d6sIGyYKIGR4CCjosNj
         GqbROkvWq0QvDmTDuZ5AAbpN2aTkK1SfzShMa3LSYkMf8BnWjcQnBMnARniS5vGJCcNR
         546A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Y35VZRZ3;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CUfD6ZWofScSR3zLBPL1W6ZHUau7G95UmAsedPjK2Cc=;
        b=CdeRsK2lOt/adnsl4lEZ9NZgcf3/i3MjH9LXBV7TfPh1+53O+3HMFk2sbKINu8PMuw
         b+RMn0JmVRERDmuxxsoJ3ldtDqMv/uQ0VLcBmSrS1j4HeJywbeogpGLPB/H4eDFxKqKX
         pYh7Ln6PDI0CFC49267GPXXGypLNAEy1K4q1Ks0NxVjgUKK0A8iyO7Sp86Okv0dNqGZG
         VdMnXG+3HMcFIKLudohfrDld+cjMOJ0BkdNcGO2AVrvX9eKRJIzxyuy0vxn5qUMvnVZv
         uH674PRhl+Jdl/r8OLAtifjhnqOviDLmVDTR4mgVUB6Y0BqkmAStSOSsvXmgN9JebYRN
         LzRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CUfD6ZWofScSR3zLBPL1W6ZHUau7G95UmAsedPjK2Cc=;
        b=ErkeHOAqxdxG8YFHzPcYLM/CHaU2ZkBr3EuP+SAVnU9nu6fAa3P30KaLJPN6ZEh21y
         vS7vvUvYpYDbxYUHlZlkWkQ0Ey3lJYhoO4bhSXdOwIICWrzYMwKrvrLwPKuW0yQzOYXb
         MGldd5Q4I/Eb17MbD9j08QCCMrwpkBDw5JrMjzNRGCHjbBGcb++rCBSDzJJJSUwss0Vg
         6dhhR0ObXntyt2m6OqnPkIc8YMoRCwkqsLwoJoW5E3+VF8W1yjbc79qHTDmmedKC9GTr
         pdmwbd+zKvYK6c83cXjM5VgZhjFlPQkVaBzlXn0ZGvtjXn3MyGG0P1JHJeZpb4Lz5AcF
         hR9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532j6fvyIu9PDBCDQyALRjKz+q8T63pMIP24jDccr7YqIe0LSALB
	QhfA1LZq3Gn1smCx6CzJSVE=
X-Google-Smtp-Source: ABdhPJyuTOaRa9o4xKY4S1QSwKHxBlhGQHyLWSwlfpCiEAaIeFO0nb/Yt+yjL3Lmaw8Era+4qrHWWg==
X-Received: by 2002:a63:235c:0:b0:3c5:f761:12fd with SMTP id u28-20020a63235c000000b003c5f76112fdmr16432252pgm.416.1652734038946;
        Mon, 16 May 2022 13:47:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4d0e:0:b0:3c5:ecce:2c37 with SMTP id i14-20020a654d0e000000b003c5ecce2c37ls6056547pgt.5.gmail;
 Mon, 16 May 2022 13:47:18 -0700 (PDT)
X-Received: by 2002:a05:6a00:ad0:b0:50a:51b3:1e3d with SMTP id c16-20020a056a000ad000b0050a51b31e3dmr18997130pfl.18.1652734038268;
        Mon, 16 May 2022 13:47:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652734038; cv=none;
        d=google.com; s=arc-20160816;
        b=dEokFq9ydyhEdkTbFBe9K7LYmcx0j6Wzgt4k9P5P/z3HVCKObp6wsQBSvtNU/Yv/6k
         FNdnqqn/E9lenfkpBpRAVttmC+lYUPrjemFajOHCS5E3K1UDtrpvT/9J5XPACbR1ai1l
         UhTw+fUg7OX9UaHVkPI3jKzt9duszfh3ifv7O+C52Ign5Vnyb2xxvpcegHVm7asg3Ux2
         CpDr/At+E2thY90U/49iWRLPCUGtTKmRlBVhZLQnM0kWsESi5kn8mXfW/SqAMru/rZz7
         1FBgwKMQARYzOsCX4ubRdv9gLO2yj3iglO7l6Pme5K24TDt0NChEay1Tr9tTrxXvN7DD
         ZvDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=iZocQ0mpc3hur9tURCsOk1Dq+fSKi2tnE//Yd+q+e1I=;
        b=Ek8SFQGXZaNTzbpUSqbu+M/rdnww4NDZQy75rsagUcemo/FkJEZ2FzOOUhfoZn27NS
         Gp1DQ1LoSf/dSIexfR87S9iQoOjWCokllUzYqNB5SZWxcaZLWZRUp4NqUUO6OywO4FrO
         jw07HLpy9x3s0WB6b2uGVbopETkwfiCND63iXfY6/m1Ip4frYi7EbSiPXgrDugIkPBn2
         d2niMpIS0dHzJCYu9CNIe/nagPXuvVwehrLa/lZCd75oRYSokfa8FC9vuaQfiY507Mzq
         ZFv2qk10GBy0uRlu57wSAAQoa7Z90D3h47UETOPkwLr3sk2rf6PN5r09aJH/xLRn3eLt
         85fA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Y35VZRZ3;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ng15-20020a17090b1a8f00b001df25a64c1asi31653pjb.2.2022.05.16.13.47.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 May 2022 13:47:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id B11DB614BA;
	Mon, 16 May 2022 20:47:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BA677C385AA;
	Mon, 16 May 2022 20:47:16 +0000 (UTC)
Date: Mon, 16 May 2022 13:47:15 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>
Cc: Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: objtool "no non-local symbols" error with tip of tree LLVM
Message-ID: <YoK4U9RgQ9N+HhXJ@dev-arch.thelio-3990X>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Y35VZRZ3;       spf=pass
 (google.com: domain of nathan@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Hi Josh and Peter,

After a recent change in LLVM [1], I see warnings (errors?) from objtool
when building x86_64 allmodconfig on 5.15 and 5.17:

  $ make -skj"$(nproc)" KCONFIG_ALLCONFIG=<(echo CONFIG_WERROR) LLVM=1 allmodconfig all
  ...
  mm/highmem.o: warning: objtool: no non-local symbols !?
  mm/highmem.o: warning: objtool: gelf_update_symshndx: invalid section index
  make[2]: *** [scripts/Makefile.build:288: mm/highmem.o] Error 255
  ...
  security/tomoyo/load_policy.o: warning: objtool: no non-local symbols !?
  security/tomoyo/load_policy.o: warning: objtool: gelf_update_symshndx: invalid section index
  make[3]: *** [scripts/Makefile.build:288: security/tomoyo/load_policy.o] Error 255
  ...

I don't see the same errors on x86_64 allmodconfig on mainline so I
bisected the 5.17 branch and came upon commit 4abff6d48dbc ("objtool:
Fix code relocs vs weak symbols"). I wanted to see what 5.17 might be
missing and came to commit ed53a0d97192 ("x86/alternative: Use
.ibt_endbr_seal to seal indirect calls") in mainline, which I think just
hides the issue for allmodconfig. I can reproduce this problem with a
more selective set of config values on mainline:

  $ make -skj"$(nproc)" LLVM=1 defconfig

  $ scripts/config -e KASAN -e SECURITY_TOMOYO -e SECURITY_TOMOYO_OMIT_USERSPACE_LOADER

  $ make -skj"$(nproc)" LLVM=1 olddefconfig security/tomoyo/load_policy.o
  security/tomoyo/load_policy.o: warning: objtool: no non-local symbols !?
  security/tomoyo/load_policy.o: warning: objtool: gelf_update_symshndx: invalid section index
  make[3]: *** [scripts/Makefile.build:288: security/tomoyo/load_policy.o] Error 255
  ...

Looking at the object file, the '.text.asan.module_ctor' section has
disappeared.

Before:

  $ llvm-nm -S security/tomoyo/load_policy.o
  0000000000000000 0000000000000001 t asan.module_ctor

  $ llvm-readelf -s security/tomoyo/load_policy.o

  Symbol table '.symtab' contains 4 entries:
     Num:    Value          Size Type    Bind   Vis       Ndx Name
       0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT   UND
       1: 0000000000000000     0 FILE    LOCAL  DEFAULT   ABS load_policy.c
       2: 0000000000000000     0 SECTION LOCAL  DEFAULT     3 .text.asan.module_ctor
       3: 0000000000000000     1 FUNC    LOCAL  DEFAULT     3 asan.module_ctor

After:

  $ llvm-nm -S security/tomoyo/load_policy.o
  0000000000000000 0000000000000001 t asan.module_ctor

  $ llvm-readelf -s security/tomoyo/load_policy.o

  Symbol table '.symtab' contains 3 entries:
     Num:    Value          Size Type    Bind   Vis       Ndx Name
       0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT   UND
       1: 0000000000000000     0 FILE    LOCAL  DEFAULT   ABS load_policy.c
       2: 0000000000000000     1 FUNC    LOCAL  DEFAULT     3 asan.module_ctor

As far as I understand it, the kernel uses constructors for at least
KASAN and KCSAN, hence why that change impacts the kernel. Beyond that,
I am not really sure whether the LLVM change is problematic or objtool
just is not accounting for something that it should. I am happy to
provide any additional information that might help understand what is
going wrong here.

[1]: https://github.com/llvm/llvm-project/commit/badd088c57d7d18acd337b7868fe8c7974c88c5b

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YoK4U9RgQ9N%2BHhXJ%40dev-arch.thelio-3990X.
