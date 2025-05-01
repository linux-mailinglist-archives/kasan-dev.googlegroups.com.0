Return-Path: <kasan-dev+bncBDCPL7WX3MKBBD5AZ7AAMGQEDRTF2OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id A7622AA643A
	for <lists+kasan-dev@lfdr.de>; Thu,  1 May 2025 21:48:32 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6e913e1cf4asf34452966d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 01 May 2025 12:48:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746128911; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z8zNmEIs/ddlwSv2eu3wEp00X81TolI9l1lHMc5L+75/KiP3IZKFIZIQ/ET5RjEE+9
         nItxngGMGCp/FSql3Z5mCKM1y2b8qSszWlfDMPS4gYzJ/W8rYI+n84UVU2B6N/6WNGWp
         7wqWDVphKAS0kZ2NUVenwM0KaaXKcB588m9dKc2ZefYoUqlVxLiQBSIiQzzEtDHBE32z
         WcUbo1chrG8kLnClODf8DfL2UTKud8bwY1WryEX0nFpruAiVegfDJB1V8Ue2PMM5GDAz
         oOeuBkIvJ1gJBoC/cE4Mr1HgQfs1ENjtY5939UsIJVb3CkZ/j64/IWqfkP0xwbVnrcKk
         PILQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=2BNW0o5rKXEzyhMCj/k7s3aGMY9RB3TCEkWeP3q7jG0=;
        fh=zbHdMQKJIQPoWLbhKAJISIyZ9yGc8wpFS9oQ8MD28MU=;
        b=dv7mtLmcWucVkCaB7HcjBoo1uv/wd4LN1+kJllAJEBJZmF+OeBdg1BHDGqOCXvrKDq
         92PNgBeMdhKuEb7azNOM/WTx77mRQ8wJdWFlHzSCyuD0NS8YxcjQ7tKSbJJ30/ITgEH6
         tgk8hhHFfmSwye4cSZPQy6sRWwrdfVhjMxPrMPF/aQshfRID1dxYuHu0tRWHbKNFy1Rq
         TuLgovsZswAjMyY9rpTGrHF3Fe1Vg7dyzCh2TiQhXTKRzxWnIrrnK/SzM02DAZZneMqn
         GOSs5gOqWQFnpJnO7ExkmukkF91maTwHHw1nOnK2fEpC9PunmgKAGTarxYyC1yLT7jFd
         V1Cw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YzGLO6k6;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746128911; x=1746733711; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2BNW0o5rKXEzyhMCj/k7s3aGMY9RB3TCEkWeP3q7jG0=;
        b=vuhovvff3FHggnguFLNiZpDu98WPnunNDVon6YtCPqFLICOjLXusYxrTpO8p4dV2jV
         SZrq/9tihqbGxVnFoLw8NJ6Clg9e4nGnydmRvInBED/I+K0KdmsUioVyGt+rG7bvdAAP
         afxUut4YyZg/Cu3AD3jgMMbGb8dmkbodOnreGslbGnbN8Vxyytpmaqdh53aqk4B4x8D7
         vlyKk6aBuUmbxl/oU7iu7LqH63elycV30uBvLwUNUTND02+nalGdDo/aQDD30n3+8Ace
         gPGuvGHC8rb9HJ8i/jlsrCqe6Q5+ZLIZOJcPZKr4JS2T+bTLOiT7NFGojEg5PI9lxnxX
         J4Hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746128911; x=1746733711;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2BNW0o5rKXEzyhMCj/k7s3aGMY9RB3TCEkWeP3q7jG0=;
        b=WJ1GHYZHe9GoWIOZDPl0ASTJimBdACX94Wo6YnkrlvM7NAE8jTzaNaQhNl0MVsLBoa
         xekbln/FtvgqrX7WNivcqMbGf9615OjXoSLiM0aCnutHnWVsg0E/BJZ1oDgjmsfpn0N/
         eY03nUBea40gcySFsrXtXZneMwioOt3g4Rbd/nrUxN1t7cZm0v9Y7BUw6qcaUkJdKm2l
         hZJFjmUiCdBFNYeedgOM2wgYz7Jw9Nd5hdcmQBA0DcBAF99dTl8f2PjwQOFy0Ut676Hk
         O3llrjfhTl4KeoSp3MZAFC9JeeeRDyJgRyJJGH7JNN4PInq5WpdjfGfaF1J/XHEtYBFX
         vWlg==
X-Forwarded-Encrypted: i=2; AJvYcCUmVTNInxN8wcrkjayftUN0MIXKhEI2AuwLoo+3gCCM0m1DzTcgxGER3j2pq+bVfcwSsJ1ZcA==@lfdr.de
X-Gm-Message-State: AOJu0YxjmaC575RmA9dhvqZmxOMt7l0BvweCWYnahvOYMkNUd73wgdL7
	rML5O9hI3iWVAGUhiNWwWxKIyZW7VOGfTMXsZXAQUVmTpW+v9lzC
X-Google-Smtp-Source: AGHT+IFPcZyHZe3Aoo129tuoRsit2rdlzQV5SZ7e9emkgS97dkCxWtAcvPYAfw+U3SgVAd+LUIrXZw==
X-Received: by 2002:ad4:5caf:0:b0:6d1:7433:3670 with SMTP id 6a1803df08f44-6f515255e88mr8928556d6.4.1746128911189;
        Thu, 01 May 2025 12:48:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGOnItINlRmC5et9y/RapOXpxDdUZJ+qogL7V1onCwFfQ==
Received: by 2002:a05:6214:212c:b0:6f2:bb36:d3f3 with SMTP id
 6a1803df08f44-6f50850264fls23670216d6.1.-pod-prod-06-us; Thu, 01 May 2025
 12:48:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX3pIIBu5K+tgOCibHH5eFAXYUwhcEaMr6rJwdX2o4E5+NvKMIH70HLFIwV9YPj3QDgVUb/f+Od6Go=@googlegroups.com
X-Received: by 2002:a05:620a:248a:b0:7c5:544e:2ccf with SMTP id af79cd13be357-7cad5ba79femr41027285a.57.1746128910373;
        Thu, 01 May 2025 12:48:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746128910; cv=none;
        d=google.com; s=arc-20240605;
        b=ODT1IqeP7VL7Ue18HxsqU4RgX+zk86aBTfqshfwrqqc6ngsMJwVFg0w9C+Wot07EQ2
         wQSM8PAei2FPa2iHkiMUa4Gsz2lcS4Zw+9koJpW/oZ41Yf+n422AksO4YMEAWbVJ6YES
         wQL7EuD7c34ZG28Z9x7IYSTRZbLW5KPREgPF/kWl3qdMtjH1rrMXDTCrdtvAgJn9YRCA
         y0iA/AuUq4Zk+pqxqioCcxLFq1Yx7Jg6ZK1MTcNxYPHQ9SPVCETmCYBa/FkOZNrJyz2m
         GmHxcbx1Oo7BSTKRxt0H1y+UAkJYXlTgYIl86ptc1S8KXx6XfBzwDjPL5dCkkDTBUFHh
         n0RQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Iy8ZdZQkk+7gbCIO/nCGCZLSjXC15Wqb01n73ukyq1M=;
        fh=fHOVEhWB8OVUqRNL6xwHPdMbEAKZhs3i69XoqdVaDV8=;
        b=gSYWntxLc98ZOOYa/xPONbHUW7sa7V3Xvb1IGb8zhqsBMskEPWwWDxEV9dC6JPQylU
         OVlJeYlcEb1pBs0ggmlDf2vpwQzb51h+bSJcjY9fzwpXhST3C8t3UvXOFSjjheeJjbw2
         dGvihP0I5K24iHjzbqySdmLCjejUbvAWdnO9LecNyhHlwPK/p2divmUNBGJvt3OZrl6n
         PoABv1gVDL9vm7C1oRLaNuJtBmwFHNH5gzcLipBFs+sgBgjrFKVn6MWkuLZr6YJRgTKb
         DluZ7xv/8yI75lSiJpz1gTD0QkDELCzgKKRMbeoBNlRSQZVvYMm7Y9jk4GWIRIWp/Tkk
         lFxw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YzGLO6k6;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7cad2430313si6322585a.7.2025.05.01.12.48.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 May 2025 12:48:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id CC18C68443;
	Thu,  1 May 2025 19:48:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 18920C4CEE4;
	Thu,  1 May 2025 19:48:29 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Kees Cook <kees@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH 0/3] Detect changed compiler dependencies for full rebuild
Date: Thu,  1 May 2025 12:48:15 -0700
Message-Id: <20250501193839.work.525-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1927; i=kees@kernel.org; h=from:subject:message-id; bh=nDhsL2XJXp4sGdblMuXDz6J+s9arRNEgRYmTCyaexrQ=; b=owGbwMvMwCVmps19z/KJym7G02pJDBnCFxh2/PXlvaehL1H6dc75Bx/zNktbhx09/FdmltqcI 0HqoR7HO0pZGMS4GGTFFFmC7NzjXDzetoe7z1WEmcPKBDKEgYtTACYy4wAjw2mV5XtjyvZEd0dd O3P41KcpP2eIZ6esbruk8vGX2Bsf0ekMf4WEFA8eXy5n9yd9Q8DhFWJR9nNPKmfrP4owctS5oT/ 5IgMA
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YzGLO6k6;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

The best way I found to deal with this is to use a -include argument
for each of the above cases, which causes fixdep to pick up the file and
naturally depend on it causing the build to notice any date stamp changes.
Each case updates its .h file when its internal dependencies change.

-Kees

Kees Cook (3):
  gcc-plugins: Force full rebuild when plugins change
  randstruct: Force full rebuild when seed changes
  integer-wrap: Force full rebuild when .scl file changes

 include/linux/vermagic.h     |  1 -
 scripts/Makefile.gcc-plugins |  2 +-
 scripts/Makefile.randstruct  |  3 ++-
 scripts/Makefile.ubsan       |  1 +
 scripts/basic/Makefile       | 20 +++++++++++++++-----
 scripts/gcc-plugins/Makefile |  8 ++++++++
 6 files changed, 27 insertions(+), 8 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250501193839.work.525-kees%40kernel.org.
