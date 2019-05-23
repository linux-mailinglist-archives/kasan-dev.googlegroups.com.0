Return-Path: <kasan-dev+bncBDQ27FVWWUFRBV63TDTQKGQEHCQEQOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7666427565
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 07:21:29 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 63sf3083163pga.18
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 22:21:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558588887; cv=pass;
        d=google.com; s=arc-20160816;
        b=ehbVhH8a52nCU3PwJ6wujoIQyG548ku/aDyDw+IAgK4sFyYxYq2okZb0RDi5U6WA4d
         SUVbNkePiPbQ5pWq3gY/uiRfhrHnTd1uippjgD2H5OEUwMlZQkm1jG5h0Y6Nvn62mPvx
         hiXOwguemtEvrD/MZXYUlYs7Cd/BSruGOmBQ8HgEaY+LPlUsAOFPVdUAPF7xF33+B9Un
         j/2BeqhLFe/ahjTSiSxVkg16b5Wr/sb5n/uY+gydPi6jIP16lFP7/qB1nGXSTNu6tpZ6
         Ag/wapkmBsNGnxBYKFwQMEl2NpquXYhAmC4A9wvdk2v4JRNJ0g/pUQvp+O0fVEHvEiw/
         XS8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=dJjLF2OtADPk5d1t9vLAhXGPN2cGNhC/gYuCZ6MIimg=;
        b=CeOtdANaBegzE45lkpuXC1JtxtZxTsVKu4jGUwh9XBuPZhhP6l2HSn3T4hsdspT3wX
         9/84o36jo5BzVATCAFn8hqijbUyoy9k0EjRwSrxUQOwVolKD7Tk2KvuuT2i+W5g4p4kN
         JNAGBn/iqGs9dTy9+DWVLJJg7mzpmDPXdtpHSsD/7xnoj0Br5BWqKUZ7lY7fGgVjY15F
         iDB8JGNuX6EokoxsE2hmio7ool7XZFp7omxl2IrXPJ2mLLvkE2lFvrr1MsSrfnqfC3pF
         43l37nwIzINto4G4WUDSfL4+seHiT3avWUKazX6Qsszo8stBnPCd2FHFOfT8JXr9kerz
         TNxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=JbAFrb3W;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dJjLF2OtADPk5d1t9vLAhXGPN2cGNhC/gYuCZ6MIimg=;
        b=Qvd1ahUYeb/eJX4yWu4QKWKNc+OGw06XgsnRrHTh2L/PfZfA83sJRcFHx6oGY6hh7k
         6E0YZWFS3Z1KQ8+hzC67HBi3dkyeL17sGRJBWXT0WfVckhgiRGn/IUi7/Lq0AFZP/LWc
         pKk8NSwfKFVEnaYQxv/+t9omFLtRcTftZFn930O718HXjvSTRhlT8X10VH94KXujKf31
         t6sOjSHe23hnTxhsFRIZIyOFiE6sh7L5WWIUuAt1WCiSjjFGmyonSSJliGTXlYYXxv1z
         UlwEn/i1N+kB/RxPk11T089cLqNJp9+WMSR1tge5wvavihAJLUi0HKRxjp9GBK9/dQ7y
         bN8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dJjLF2OtADPk5d1t9vLAhXGPN2cGNhC/gYuCZ6MIimg=;
        b=P/JiKMxtcexw5x5t4Lg0G0J55lCxj/dKdVdcEVNBbzKyab7+rLCwuOInvS9DhTd4rW
         EY1nCwlCoGRb8/pNxrOzn7gjWFasQrtGU4RNCSAMmOT89/nAvZAbRyt7RCT7hTI92Hgg
         CtYubbSaY+pmRuV64aFpIqK9IO8+3rt1ZxZ4JVNI230PBM7TUmVXEfblJCjqEQGWs4eq
         btgkkIu7DCCUVLWtZSAtwme5V3WQ7r7W/ME55Vro5KaHJ32dGMccDYItEjxGw7ue4ZoF
         SlEGsqcHZ32eXeoiRhXRz+1hafrUvSaQ2QNBk1wj08Ga6IulVfCr44BvION+moZghSHk
         y5qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWhBsuvQOuMHphX5O7yxJ3WTFrvJQqaE5gTYNPCHgRV7LmoL8bE
	wjb3DaxpPavYjN4aSo5G4bE=
X-Google-Smtp-Source: APXvYqwZAaadWpYqFdKkhFub49Y7V0E25SSjAosgTjD0rrwKf4HvZdVC6Gd/yIsg++dzNAzhq1db1A==
X-Received: by 2002:a17:902:3383:: with SMTP id b3mr49391098plc.193.1558588887667;
        Wed, 22 May 2019 22:21:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:36cc:: with SMTP id d195ls1190314pga.6.gmail; Wed, 22
 May 2019 22:21:27 -0700 (PDT)
X-Received: by 2002:a63:fd0c:: with SMTP id d12mr94880130pgh.391.1558588887372;
        Wed, 22 May 2019 22:21:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558588887; cv=none;
        d=google.com; s=arc-20160816;
        b=OhZYwLLKz1sIYn/f/HiX6GjykP4Vr5fi9JF4o85/09dPSuxiodmfLaTRiU2+xkEOJv
         jjWyOHjDFjnfeN5+KsRPnlj1MfabwpKoek+MQXiUKBS6fmuPeYZUUHqmjPyTL+E32RDD
         Nj25+fFS4DHoGVRUtBCJcvJoRXwUqSRDepN0nci/Q613xu3/WcuKmVn/8v2phggGIyQK
         XUl8gbW3bN+28evPl1gJyWd1sm/qPusCZ8K2w/oFjbXI/h7yFAaM9QwoJVkyRJJzSCuE
         VnNyMT8DhmLvKID2elJ3K+Z9zTRsBNj0u39PAzB1ZSlQ78fQvOZ4Ea0aR0byMVK0ct8F
         G5BQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=PjLS5rjwECt47OrrJ3GKr48ugpffm8kjSMiiZ4w9zRw=;
        b=O9nFWQBWVHJP36a6xNkN24UXcAlgPuXV3DKBmxbu5j89uNSSLx8FMQitDUd/XduIU0
         fjc5VCtuRkepdGNze8zK+tDIqt2rgX61m1ICS6j9WpE70dd5ZjDXu4K+KY+61AUwKlx5
         GfCJXPySmCFR1QXOUio91aKV4HYSyUehnMUz5nC4LSCNvXRkSBmG5Yy4WPx46c/btjp7
         xvPUuniADiP3TIc6Ohx0u6OfdwZH9tjPEM2X621wZj2yq1jG3vMqXDWSOcS8GzLSKrdh
         bXFe9lkhZq+LWJqR/1aJv/UIY+7RjdIjmtvCfyEtKGR4YsSqFEpaaSCZypqyIj5cuum5
         5X5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=JbAFrb3W;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id f184si1211677pfb.0.2019.05.22.22.21.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 22:21:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id c13so2499953pgt.1
        for <kasan-dev@googlegroups.com>; Wed, 22 May 2019 22:21:27 -0700 (PDT)
X-Received: by 2002:a17:90a:b78b:: with SMTP id m11mr197936pjr.106.1558588887061;
        Wed, 22 May 2019 22:21:27 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id g83sm45134574pfb.158.2019.05.22.22.21.25
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 22 May 2019 22:21:26 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: aneesh.kumar@linux.ibm.com,
	christophe.leroy@c-s.fr,
	bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>
Subject: [RFC PATCH 0/7] powerpc: KASAN for 64-bit 3s radix
Date: Thu, 23 May 2019 15:21:13 +1000
Message-Id: <20190523052120.18459-1-dja@axtens.net>
X-Mailer: git-send-email 2.19.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=JbAFrb3W;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Building on the work of Christophe, Aneesh and Balbir, I've ported
KASAN to Book3S radix.

It builds on top Christophe's work on 32bit, and includes my work for
64-bit Book3E (3S doesn't really depend on 3E, but it was handy to
have around when developing and debugging).

This provides full inline instrumentation on radix, but does require
that you be able to specify the amount of memory on the system at
compile time. More details in patch 7.

Regards,
Daniel

Daniel Axtens (7):
  kasan: do not open-code addr_has_shadow
  kasan: allow architectures to manage the memory-to-shadow mapping
  kasan: allow architectures to provide an outline readiness check
  powerpc: KASAN for 64bit Book3E
  kasan: allow arches to provide their own early shadow setup
  kasan: allow arches to hook into global registration
  powerpc: Book3S 64-bit "heavyweight" KASAN support

 arch/powerpc/Kconfig                         |   2 +
 arch/powerpc/Kconfig.debug                   |  17 ++-
 arch/powerpc/Makefile                        |   7 ++
 arch/powerpc/include/asm/kasan.h             | 116 +++++++++++++++++++
 arch/powerpc/kernel/prom.c                   |  40 +++++++
 arch/powerpc/mm/kasan/Makefile               |   2 +
 arch/powerpc/mm/kasan/kasan_init_book3e_64.c |  50 ++++++++
 arch/powerpc/mm/kasan/kasan_init_book3s_64.c |  67 +++++++++++
 arch/powerpc/mm/nohash/Makefile              |   5 +
 include/linux/kasan.h                        |  13 +++
 mm/kasan/generic.c                           |   9 +-
 mm/kasan/generic_report.c                    |   2 +-
 mm/kasan/init.c                              |  10 ++
 mm/kasan/kasan.h                             |   6 +-
 mm/kasan/report.c                            |   6 +-
 mm/kasan/tags.c                              |   3 +-
 16 files changed, 345 insertions(+), 10 deletions(-)
 create mode 100644 arch/powerpc/mm/kasan/kasan_init_book3e_64.c
 create mode 100644 arch/powerpc/mm/kasan/kasan_init_book3s_64.c

-- 
2.19.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190523052120.18459-1-dja%40axtens.net.
For more options, visit https://groups.google.com/d/optout.
