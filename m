Return-Path: <kasan-dev+bncBAABB5FSTT3QKGQEEC3C76A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-f185.google.com (mail-pl1-f185.google.com [209.85.214.185])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CA3D1F8E10
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 08:47:17 +0200 (CEST)
Received: by mail-pl1-f185.google.com with SMTP id p3sf10394116plr.3
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Jun 2020 23:47:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592203636; cv=pass;
        d=google.com; s=arc-20160816;
        b=NTBvx5FG4JvHicYrL1t6plB2cJavZ8a8rkQBmqrvp0GdzKsnmirs9sl0wpe7884dE0
         uMUjGLE5O6Vxgc+ia0/3zgMvD6+1k3AvbpD4pCRuKWZivuiOck2rj0rmCQzJ/YRQJ3EO
         oMD3WiNYNVq8nRimtuqOoV8cUNZRTpqhRmzLNUmBzOL4SXBD2wuIVfTQKQNpGEGDQ0ji
         eAF8lwv9ZYTNt1bMaaVdJovoZlurOM99qyAgCt9GRXqAZ98OM2r1ql4qkdd2G/tMr+bM
         P7dpQN8SMQebkq8Ir7zwoOzrDuT2VLW81J+ejh3ldELHNPc77beN6MdBU6OCU7WfjRp8
         zpuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:mime-version:message-id:date
         :subject:cc:to:from;
        bh=B40SkJuQAD9SShZ1LuAv3Enbp4fuE6J0Mz/xP1SVFmQ=;
        b=MciQU7R2sOjAvGcD7mmJmBqXANaVhB6e6yOglw4jg54uEyPbfOXgzNUKItqLGMf+iv
         QqvHCrc2HwsrRLRky4eAVvkD0QMLzjcTwNJOlx+YeztCw2Ac7cw8q0rc5nanN7WvS78C
         VyZt8SjdOQyrMYNR/UWJwG7grie4A+/g8lOplFslNpEXeWk97U3zcRmYwBj35LFkd91G
         Moyw+oXVnRBNcEjV7hgQ3ThZtqLmOcRiIpFKoyUmhTBuRKkCiXhjqQ5cKX92Z5r3wQ3q
         qFEoc2lgfTPM3Jp/xn0/3twmdin+7etieWT1mlAUN/m8kTqjpp+XwC0MZeABXjXIvTdg
         CzyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=fkfERACX;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :sender:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=B40SkJuQAD9SShZ1LuAv3Enbp4fuE6J0Mz/xP1SVFmQ=;
        b=oIGxycZwGlzPeBMLZNPAVwL8vp0Mpyhv5gSx8Bhmywffycb0WGxXEKYUkqA7aCf7HL
         iBwemzFllGgHzWgJubu718dbCZSTWeEhkwndyyzNBs6i7aonVnASOIgTdn2RjRXHy+XQ
         IRtzu6clXNwk5bIOOtJwngOZ7hIsedQnwGGQejQ2yJ/sIzoCMLbWEccq8pV/r74F3AQW
         3SQPXfDIvism0tCVfbCGMdDhfqlDTNwAeZ9h/Sa5PC36txka3iIEKVe579xS8ZqOJerS
         2iKhnCfRYEPo4DJZXmXAbW+BSqLux3ZH3l3Z3rqKa1DgUm0kH9TIsKVwv16BbUAjxYVZ
         jxag==
X-Gm-Message-State: AOAM533ZNT2QLuXA2tS1T9pn7hKDHsbSnoIoVpKkSmdxibU2Ne4CoGmY
	xNaXA5/ecA5+ssoZHyW1Ybo=
X-Google-Smtp-Source: ABdhPJyOQ24Kom8G5pBaOPXlUK2HK/4D1ej6I5ZYT36/gx4HCF9Jp2HjLzGx9oRLJXqorjXGUojyYQ==
X-Received: by 2002:a17:902:b60e:: with SMTP id b14mr21158372pls.81.1592203636279;
        Sun, 14 Jun 2020 23:47:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:820e:: with SMTP id k14ls3213628pfi.8.gmail; Sun, 14 Jun
 2020 23:47:16 -0700 (PDT)
X-Received: by 2002:a63:455c:: with SMTP id u28mr11171595pgk.374.1592203635969;
        Sun, 14 Jun 2020 23:47:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592203635; cv=none;
        d=google.com; s=arc-20160816;
        b=wtRK8ECftsVPS+B1O8+sX2cLsIb4ZoMjkaS1BIrrvQSIZ0UmM7ZomC4XzuqLpU3WuB
         Eqy560d+8YsMXSBgDX2fy5xg57FNAewQ8jm8VN9WQ04gmjxwqMLLGTZGTs0ORBsXVR5d
         zlWHGk3zP2XXPA3wMnnHGNnwtvThLR08bQ0/EEpJ2/uzCZywRLIxPCIFFDrb8QLl9IyO
         KErg/91kkL47ntNNbt6k7BWJX+CDEmB08kScKSV9L0Llc8a9btkvLN321znc30/K/sM5
         TL98SZZ99hbS/a/ITvyxNRFnolb/5Fgg4PZJ7jZloBjduHdxzGhVh8I/HxBRbExLSnAX
         +dHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:content-transfer-encoding:mime-version:message-id:date
         :subject:cc:to:from:dkim-signature;
        bh=NM9B5cLok6jXcY4Ox9DT1pLFN5xhmuT2OpZKyoOfihM=;
        b=kke4nlWdcILZpDtMEHh0aDVf1v6tJ6dF4lbESg3Pkp84a98VLXWyYyEoXwfrzijDZs
         4r2G1WroCMSm18eCYavtd35m0HGHo2WoD7U+cNpKxhBfV/m/Kl5AQTox7TDf7/K/g4UG
         I7LEzd4YtdTFsxUp69xyHyWD4dFdi7+FaE/2sG+Buu33orJhnu0IAsvoh6RwTkkvZC17
         wo/9UQ+3D3hEE7F54JiyQsouBfWV3qYH3+a98CZdgo8PfPTx7KQqGcnq62MB8a0keLyo
         0XaL2Su4VLncqr63vLpwZWZooowAySLJyiFAdRYU/jQTkqfZ0j1MHHZv7KoE6Ts3VXQU
         soqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=fkfERACX;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v197si934899pfc.0.2020.06.14.23.47.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Jun 2020 23:47:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail.kernel.org (ip5f5ad5c5.dynamic.kabel-deutschland.de [95.90.213.197])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 75D7A2074D;
	Mon, 15 Jun 2020 06:47:15 +0000 (UTC)
Received: from mchehab by mail.kernel.org with local (Exim 4.93)
	(envelope-from <mchehab@kernel.org>)
	id 1jkith-009nlx-C3; Mon, 15 Jun 2020 08:47:09 +0200
From: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
To: Linux Doc Mailing List <linux-doc@vger.kernel.org>
Cc: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	linux-kernel@vger.kernel.org,
	Jonathan Corbet <corbet@lwn.net>,
	Alasdair Kergon <agk@redhat.com>,
	Mark Brown <broonie@kernel.org>,
	NXP Linux Team <linux-imx@nxp.com>,
	Nicholas Piggin <npiggin@gmail.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	linux-kselftest@vger.kernel.org,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Thomas Gleixner <tglx@linutronix.de>,
	Mike Snitzer <snitzer@redhat.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Geert Uytterhoeven <geert+renesas@glider.be>,
	linux-ia64@vger.kernel.org,
	Bjorn Helgaas <bhelgaas@google.com>,
	devicetree@vger.kernel.org,
	Steven Rostedt <rostedt@goodmis.org>,
	Jaegeuk Kim <jaegeuk@kernel.org>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	linux-gpio@vger.kernel.org,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Sukadev Bhattiprolu <sukadev@linux.ibm.com>,
	linux-renesas-soc@vger.kernel.org,
	Will Deacon <will@kernel.org>,
	linux-rockchip@lists.infradead.org,
	linux-media@vger.kernel.org,
	Andy Gross <agross@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	keyrings@vger.kernel.org,
	Sandy Huang <hjc@rock-chips.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	Christoph Hellwig <hch@lst.de>,
	linux-arch@vger.kernel.org,
	Ingo Molnar <mingo@redhat.com>,
	Federico Vaga <federico.vaga@vaga.pv.it>,
	alsa-devel@alsa-project.org,
	Sascha Hauer <s.hauer@pengutronix.de>,
	"James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	linux-fsdevel@vger.kernel.org,
	Sandipan Das <sandipan@linux.ibm.com>,
	Shawn Guo <shawnguo@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>,
	Liam Girdwood <lgirdwood@gmail.com>,
	Joel Fernandes <joel@joelfernandes.org>,
	Arnaud Pouliquen <arnaud.pouliquen@st.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Sean Wang <sean.wang@mediatek.com>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Luc Maranget <luc.maranget@inria.fr>,
	x86@kernel.org,
	linux-mediatek@lists.infradead.org,
	Lubomir Rintel <lkundrak@v3.sk>,
	linux-pci@vger.kernel.org,
	Tony Luck <tony.luck@intel.com>,
	Dave Hansen <dave.hansen@intel.com>,
	rcu@vger.kernel.org,
	Michael Ellerman <mpe@ellerman.id.au>,
	Bjorn Andersson <bjorn.andersson@linaro.org>,
	=?UTF-8?q?Heiko=20St=C3=BCbner?= <heiko@sntech.de>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Jakub Kicinski <kuba@kernel.org>,
	Alexey Dobriyan <adobriyan@gmail.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Josh Triplett <josh@joshtriplett.org>,
	Gerald Schaefer <gerald.schaefer@de.ibm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Marco Elver <elver@google.com>,
	Helge Deller <deller@gmx.de>,
	Russell King <linux@armlinux.org.uk>,
	linux-mips@vger.kernel.org,
	Haren Myneni <haren@linux.ibm.com>,
	linux-bluetooth@vger.kernel.org,
	Eric Dumazet <edumazet@google.com>,
	Daniel Vetter <daniel@ffwll.ch>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	dm-devel@redhat.com,
	linux-f2fs-devel@lists.sourceforge.net,
	Shuah Khan <shuah@kernel.org>,
	Daniel Kiss <daniel.kiss@arm.com>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	David Howells <dhowells@redhat.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	=?UTF-8?q?Niklas=20S=C3=B6derlund?= <niklas.soderlund+renesas@ragnatech.se>,
	Fabio Estevam <festevam@gmail.com>,
	Mike Kravetz <mike.kravetz@oracle.com>,
	Paul Mackerras <paulus@samba.org>,
	Alan Stern <stern@rowland.harvard.edu>,
	linux-arm-msm@vger.kernel.org,
	dri-devel@lists.freedesktop.org,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	kasan-dev@googlegroups.com,
	Pengutronix Kernel Team <kernel@pengutronix.de>,
	Jan Kara <jack@suse.cz>,
	linux-parisc@vger.kernel.org,
	Fenghua Yu <fenghua.yu@intel.com>,
	Akira Yokosawa <akiyks@gmail.com>,
	Kees Cook <keescook@chromium.org>,
	Daniel Lustig <dlustig@nvidia.com>,
	Chao Yu <chao@kernel.org>,
	Bartosz Golaszewski <bgolaszewski@baylibre.com>,
	Florian Fainelli <f.fainelli@gmail.com>,
	Alexey Gladkov <gladkov.alexey@gmail.com>,
	Thiago Jung Bauermann <bauerman@linux.ibm.com>,
	Akira Shimahara <akira215corp@gmail.com>,
	linux-spi@vger.kernel.org,
	Robin Murphy <robin.murphy@arm.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	"David S. Miller" <davem@davemloft.net>,
	David Airlie <airlied@linux.ie>,
	Philipp Zabel <p.zabel@pengutronix.de>,
	Rob Herring <robh+dt@kernel.org>,
	Borislav Petkov <bp@alien8.de>,
	iommu@lists.linux-foundation.org,
	netdev@vger.kernel.org,
	Jeff Layton <jlayton@kernel.org>
Subject: [PATCH 00/29] Documentation fixes
Date: Mon, 15 Jun 2020 08:46:39 +0200
Message-Id: <cover.1592203542.git.mchehab+huawei@kernel.org>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
Sender: Mauro Carvalho Chehab <mchehab@kernel.org>
X-Original-Sender: mchehab+huawei@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=fkfERACX;       spf=pass
 (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=mchehab@kernel.org;       dmarc=pass (p=NONE
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

Hi Jon,

That's a bunch of files I have to be applied on the top of v5.8-rc1 fixing
documentation warnings. I already removed some duplicated stuff.

Regards,
Mauro

Mauro Carvalho Chehab (29):
  mm: vmalloc.c: remove a kernel-doc annotation from a removed parameter
  net: dev: add a missing kernel-doc annotation
  net: netdevice.h: add a description for napi_defer_hard_irqs
  scripts/kernel-doc: parse __ETHTOOL_DECLARE_LINK_MODE_MASK
  net: pylink.h: add kernel-doc descriptions for new fields at
    phylink_config
  scripts/kernel-doc: handle function pointer prototypes
  fs: fs.h: fix a kernel-doc parameter description
  gpio: driver.h: fix kernel-doc markup
  kcsan: fix a kernel-doc warning
  rcu: fix some kernel-doc warnings
  fs: docs: f2fs.rst: fix a broken table
  dt: update a reference for reneases pcar file renamed to yaml
  dt: fix broken links due to txt->yaml renames
  dt: Fix broken references to renamed docs
  dt: fix reference to olpc,xo1.75-ec.txt
  selftests/vm/keys: fix a broken reference at protection_keys.c
  docs: hugetlbpage.rst: fix some warnings
  docs: powerpc: fix some issues at vas-api.rst
  docs: driver-model: remove a duplicated markup at driver.rst
  docs: watch_queue.rst: supress some Sphinx warnings and move to
    core-api
  docs: device-mapper: add dm-ebs.rst to an index file
  docs: it_IT: add two missing references
  docs: ABI: fix a typo when pointing to w1-generic.rst
  docs: fs: locking.rst: fix a broken table
  docs: add bus-virt-phys-mapping.txt to core-api
  docs: fix references for DMA*.txt files
  docs: dt: minor adjustments at writing-schema.rst
  docs: fs: proc.rst: fix a warning due to a merge conflict
  docs: fs: proc.rst: convert a new chapter to ReST

 .../ABI/testing/sysfs-driver-w1_therm         |   2 +-
 Documentation/PCI/pci.rst                     |   6 +-
 .../admin-guide/device-mapper/index.rst       |   1 +
 Documentation/admin-guide/mm/hugetlbpage.rst  |  25 ++-
 Documentation/block/biodoc.rst                |   2 +-
 .../bus-virt-phys-mapping.rst}                |   2 +-
 Documentation/core-api/dma-api.rst            |   6 +-
 Documentation/core-api/dma-isa-lpc.rst        |   2 +-
 Documentation/core-api/index.rst              |   2 +
 Documentation/{ => core-api}/watch_queue.rst  |  34 ++--
 .../bindings/arm/freescale/fsl,scu.txt        |   2 +-
 .../bindings/display/bridge/sii902x.txt       |   2 +-
 .../bindings/display/imx/fsl-imx-drm.txt      |   4 +-
 .../devicetree/bindings/display/imx/ldb.txt   |   4 +-
 .../display/rockchip/rockchip-drm.yaml        |   2 +-
 .../bindings/misc/olpc,xo1.75-ec.txt          |   2 +-
 .../bindings/net/mediatek-bluetooth.txt       |   2 +-
 .../bindings/pinctrl/renesas,pfc-pinctrl.txt  |   2 +-
 .../bindings/sound/audio-graph-card.txt       |   2 +-
 .../bindings/sound/st,sti-asoc-card.txt       |   2 +-
 .../bindings/spi/qcom,spi-geni-qcom.txt       |   2 +-
 Documentation/devicetree/writing-schema.rst   |   9 +-
 .../driver-api/driver-model/driver.rst        |   2 -
 Documentation/driver-api/usb/dma.rst          |   6 +-
 Documentation/filesystems/f2fs.rst            | 150 ++++++++++++------
 Documentation/filesystems/locking.rst         |   6 +-
 Documentation/filesystems/proc.rst            |  46 +++---
 Documentation/memory-barriers.txt             |   6 +-
 Documentation/mips/ingenic-tcu.rst            |   2 +-
 Documentation/powerpc/vas-api.rst             |  23 ++-
 Documentation/security/keys/core.rst          |   2 +-
 .../it_IT/process/management-style.rst        |   2 +
 .../it_IT/process/submitting-patches.rst      |   2 +
 .../translations/ko_KR/memory-barriers.txt    |   6 +-
 MAINTAINERS                                   |   8 +-
 arch/ia64/hp/common/sba_iommu.c               |  12 +-
 arch/parisc/kernel/pci-dma.c                  |   2 +-
 arch/x86/include/asm/dma-mapping.h            |   4 +-
 arch/x86/kernel/amd_gart_64.c                 |   2 +-
 drivers/parisc/sba_iommu.c                    |  14 +-
 include/linux/dma-mapping.h                   |   2 +-
 include/linux/fs.h                            |   2 +-
 include/linux/gpio/driver.h                   |   2 +-
 include/linux/kcsan-checks.h                  |  10 +-
 include/linux/netdevice.h                     |   2 +
 include/linux/phylink.h                       |   4 +
 include/linux/rculist.h                       |   2 +-
 include/linux/watch_queue.h                   |   2 +-
 include/media/videobuf-dma-sg.h               |   2 +-
 init/Kconfig                                  |   2 +-
 kernel/dma/debug.c                            |   2 +-
 kernel/watch_queue.c                          |   2 +-
 mm/vmalloc.c                                  |   1 -
 net/core/dev.c                                |   1 +
 scripts/kernel-doc                            |   7 +
 tools/testing/selftests/vm/protection_keys.c  |   2 +-
 56 files changed, 282 insertions(+), 175 deletions(-)
 rename Documentation/{bus-virt-phys-mapping.txt => core-api/bus-virt-phys-mapping.rst} (99%)
 rename Documentation/{ => core-api}/watch_queue.rst (94%)

-- 
2.26.2


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1592203542.git.mchehab%2Bhuawei%40kernel.org.
