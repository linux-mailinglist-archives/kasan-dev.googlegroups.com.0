Return-Path: <kasan-dev+bncBDQ27FVWWUFRB7M6VDVAKGQESU67QIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc37.google.com (mail-yw1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id B083A83DDE
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2019 01:38:38 +0200 (CEST)
Received: by mail-yw1-xc37.google.com with SMTP id v3sf64723968ywe.21
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Aug 2019 16:38:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565134717; cv=pass;
        d=google.com; s=arc-20160816;
        b=aYkFRwTbOM+CCGx3Ywv4RrJxG5RYWemwRbzACCczjr5bq8Ybp3al0tlKkNqbYTE38f
         V62U7Cx6bDYwEEu+MewDw27nKuVKvYp34dfkSmIqzzQyDUdNHoiofIIu66dx8N1c9PrV
         QD+o4wDngpomMgMyXveuedCczeBp52mgIS7vzeez6mwd0yC2Gxmjl2c7hwh9PhSFoY9p
         jWW5BkSaKz1jf31pVnMEdCB264PB/JcEo5KrWIeQZ/41+ptGBcV3/Jgws1jghh6fEOtc
         njwS0o9vommb5njUYOnzKoteI/vW+02zH19CSOZdj6rfKW2NDMVCp28yGQmA683XErIX
         q7rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=S7G0yG5q0SURkh02CVJ3ZdPxJL4CgmWjY7hJIa275+g=;
        b=MiEdt/2GtRRzNJgFafxPgEFPH48o0J/UdzFJO3LwQ/mXbmj8yAQBSlEyxLEpTauEy1
         QWh9Xi+Y8ertryBlHVD3wasMVLDWWVTVH7vkWj+TWUdSF7vofn3tHVqygPK8WNRfEMTr
         KTlpmLrIfqD+B9m+8/FkcbNDqFNFMtMVNi9v83ha2ogrGoRershly+5lay5gmUey4nMa
         TZRyq9iGrNUR6Se8rxjOaZ2IJSXB0RaH+AOdWw8bwnQXIkpY34ZqNBLo35RNoVaYuZRs
         Y/9fgs12H23aK9910YIPQlk5eS1hu23c2SlLkxz/IfvI5DNSUPoLqUcnhObmzg8WpjHS
         L/dQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=YF7OjRrF;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S7G0yG5q0SURkh02CVJ3ZdPxJL4CgmWjY7hJIa275+g=;
        b=d7eJ2i71CrSO28dfM7W6JZK9zBEK9GYZ/sL1Rgo0b3Ua5U3tkojVasVJY2PF5B6F6j
         iK0hlExlbcLIYJsjCmCaSk+DaV2rpMt47EfsS09Rgt2vDtii0qcBM8TCtMlyEZ09jY1D
         50UAJh9tbt9TTVw2M7GSZCgAg+CwnTdNTWJ2Alm8yIcei3IBBXGwya1m4VU2jq86WJVR
         coTpj6+/rdDIkXXWPgkqmfW1YDN2usYKcilbGTBPz/+oItoQfay/PqR6cNRgs+/mK6y+
         0H0OpiAEIhp5U4QysTpE8ONzUu04VQbh3kTroJf+QVWlosSBiBWO/aTWxIY0oYfSBGsS
         bcbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=S7G0yG5q0SURkh02CVJ3ZdPxJL4CgmWjY7hJIa275+g=;
        b=BMaMn0IZllQszZqrVVcnZaveb5mNFWHAR+uuXZ38w7oesmOvrP5+BweEwxYWuMxwd2
         6LsSTbcZGAzEaKN5rA2ncvdDhA4Dr4r7JB8EsefHZ4Y8TZ1ln0oGdEzE9JpNPkU02QAQ
         IkHbLNWj6J94suNSSVC7HnDWUCcORXNH2nbFrQ+15Z1p4ALfn3lyqv4GFzbt7FuLTBYb
         VzFhDiu6cVk1ZxOU4kjAXI40TCSqjXljpG4PbfWDvBFLKbgsmQiJzk1l+8jsyM5F8Xuw
         ex2876tZ2wBLEnbZH4u2uCzscolljFRB1PXGUQmvtMCdyP8Se+BhsDRtzYgh7cIK6nR2
         cmVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU/41D5/H6jCQXyXU3a+kHFdiSFTW67T2UHrO1h+PNdfnGPaHvI
	jELUtqQpJZRIAqL50mZ5EmU=
X-Google-Smtp-Source: APXvYqxVJgyUaU43G+xgVav568eVuNiwvv3P2xKDqOJaCpOrubXPcIOlcui0zPYsifuZs3PgsAw7vA==
X-Received: by 2002:a81:1d11:: with SMTP id d17mr4302026ywd.9.1565134717711;
        Tue, 06 Aug 2019 16:38:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:700a:: with SMTP id l10ls18118550ybc.3.gmail; Tue, 06
 Aug 2019 16:38:37 -0700 (PDT)
X-Received: by 2002:a25:ed0e:: with SMTP id k14mr4580035ybh.286.1565134717317;
        Tue, 06 Aug 2019 16:38:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565134717; cv=none;
        d=google.com; s=arc-20160816;
        b=D5YeN2xitlioEExWT2QNu9IHaGB7q8XQyWzJQVoKe0iT9CroQp4zYvZRl+K1gxn9JF
         qXTF2UYTOtVUWPwVLl8jfXZkuyvZkxYRagzfdNrPqtB5BnqX6Kh1O5K1XImrBAgwKAPe
         +7NYE5j6zZ/NL78kSl2hVTgS8mhy43qr750v2bDwD6jc3cBzwVoEH/BoMfLh9fUJRbgQ
         nxV30xvuG9YLDkbBXstb0JDeCcN1FnxNK5GJfaKcCtmBp++Bn44rYEbjy3cevcCu5QiP
         07rGhgd+bSyWxEMrh4iRi59Nc4TfRq+6NbC7BTIuUO0m3BqpvGf4pnAdmez5r0i8JPr4
         j/wQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=n86VTUimVDYp3c15YC9BaKGXMcoo6OcCYb6cMaite0k=;
        b=jLXylKpiJnlc/hpIVwRTjF/yUk2ClfJBEuY9BqznCLUTc46CC5uic8+/RjBqrREQgb
         e6vPp3e41OgKl0pvl7ve8SeSv8TnxdqU+TwJs4LT+uhoIAZqSrluVg44YHgBUwquDhDe
         O2XEWFQC7F+bc2DKZQqTvzZrnMrklmrxXCAY1l/kIqzSmuQJqmVyl6B8TiAxohCOQYg1
         pjK47LmTmyBtwFFFIuw02NAe+ACNKgSj64nF6LhsmhVF3SS0rihj2vBEYgLNeAP3jbOy
         bEGArug4pjDhcNC32DYazCSv0MPGrUU6n0Fmhtp1F/QEut2nHO4696ACa5suiGdcdvYt
         lFeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=YF7OjRrF;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id v127si3934446ywv.2.2019.08.06.16.38.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 Aug 2019 16:38:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id i2so38512346plt.1
        for <kasan-dev@googlegroups.com>; Tue, 06 Aug 2019 16:38:37 -0700 (PDT)
X-Received: by 2002:a17:902:bf07:: with SMTP id bi7mr5574545plb.167.1565134716359;
        Tue, 06 Aug 2019 16:38:36 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id c70sm63183864pfb.36.2019.08.06.16.38.34
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Tue, 06 Aug 2019 16:38:35 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: aneesh.kumar@linux.ibm.com,
	christophe.leroy@c-s.fr,
	bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH 0/4] powerpc: KASAN for 64-bit Book3S on Radix
Date: Wed,  7 Aug 2019 09:38:23 +1000
Message-Id: <20190806233827.16454-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=YF7OjRrF;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as
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
KASAN to 64-bit Book3S kernels running on the Radix MMU.

It builds on top Christophe's work on 32bit. It also builds on my
generic KASAN_VMALLOC series, available at:
https://patchwork.kernel.org/project/linux-mm/list/?series=153209

This provides full inline instrumentation on radix, but does require
that you be able to specify the amount of memory on the system at
compile time. More details in patch 4.

Notable changes from the RFC:

 - I've dropped Book3E 64-bit for now.

 - Now instead of hacking into the KASAN core to disable module
   allocations, we use KASAN_VMALLOC.

 - More testing, including on real hardware. This revealed that
   discontiguous memory is a bit of a headache, at the moment we
   must disable memory not contiguous from 0. 
   
 - Update to deal with kasan bitops instrumentation that landed
   between RFC and now.

 - Documentation!

 - Various cleanups and tweaks.

I am getting occasional problems on boot of real hardware where it
seems vmalloc space mappings don't get installed in time. (We get a
BUG that memory is not accessible, but by the time we hit xmon the
memory then is accessible!) It happens once every few boots. I haven't
yet been able to figure out what is happening and why. I'm going to
look in to it, but I think the patches are in good enough shape to
review while I work on it.

Regards,
Daniel

Daniel Axtens (4):
  kasan: allow arches to provide their own early shadow setup
  kasan: support instrumented bitops with generic non-atomic bitops
  powerpc: support KASAN instrumentation of bitops
  powerpc: Book3S 64-bit "heavyweight" KASAN support

 Documentation/dev-tools/kasan.rst            |   7 +-
 Documentation/powerpc/kasan.txt              | 111 ++++++++++++++
 arch/powerpc/Kconfig                         |   4 +
 arch/powerpc/Kconfig.debug                   |  21 +++
 arch/powerpc/Makefile                        |   7 +
 arch/powerpc/include/asm/bitops.h            |  25 ++--
 arch/powerpc/include/asm/book3s/64/radix.h   |   5 +
 arch/powerpc/include/asm/kasan.h             |  35 ++++-
 arch/powerpc/kernel/process.c                |   8 ++
 arch/powerpc/kernel/prom.c                   |  57 +++++++-
 arch/powerpc/mm/kasan/Makefile               |   1 +
 arch/powerpc/mm/kasan/kasan_init_book3s_64.c |  76 ++++++++++
 include/asm-generic/bitops-instrumented.h    | 144 ++++++++++---------
 include/linux/kasan.h                        |   2 +
 lib/Kconfig.kasan                            |   3 +
 mm/kasan/init.c                              |  10 ++
 16 files changed, 431 insertions(+), 85 deletions(-)
 create mode 100644 Documentation/powerpc/kasan.txt
 create mode 100644 arch/powerpc/mm/kasan/kasan_init_book3s_64.c

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190806233827.16454-1-dja%40axtens.net.
