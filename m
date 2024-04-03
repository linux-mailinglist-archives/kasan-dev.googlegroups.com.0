Return-Path: <kasan-dev+bncBCXO5E6EQQFBBRM4WSYAMGQEAHYYO7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id 739718967A1
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Apr 2024 10:07:35 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-61504a34400sf34932627b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 01:07:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712131654; cv=pass;
        d=google.com; s=arc-20160816;
        b=m4xnirgRIFzdQUJkidhoi82mBjn0JUghUmaegQk6vRjUry+U55es77ssx1fqwKWYop
         Pyc5B+S8PNbpmnl4kZPAtB6uKOrjAqzOefyFhX023dAbTm+QInEYizYWJ4NkJh7Rj6KZ
         xWIY75hFnkUouhTYsuAszr9LO6HpE5EXb4GCvLGcAq9mcYYuXHQnaxoCaSnbOopXH8PK
         b+BT1FgVyR7afEf6VPj6t0jtahCNGr2OdbsQc6YrmdqquJ0Logh5pgT5DviajryezoxC
         s81YGC5rDclhIfd08WxLJPPwkA5eOvBjTektc3ji6+rEHcXtPADtosubcDg+zCkGKFSo
         871w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=GVokH9vLit0JnzLAjXIqCCFqkh5uitEya9LZD8DbRQo=;
        fh=NRj4uCpemSrmZ8/NKWQ1Vm1E0YVMkEq688XkcZNo4t8=;
        b=eAe6zJhcDU8UqpIXROl+DfQEEDekdmRl9m9Gj3Op+nGp8s5TLtCZf73snsyUs/zowq
         dRc/GK32YbAfhY6aumVoWgOux6mTDDuilLiA39z+f8dlrdP5k5pTUI8hVk6G7E2rzo1Y
         KIFu6yLNBJSlwNHqsBWqxhcN9TL0U9jgpJmObj9A9rOuDC0xZYW5ohWnGLqIHVgHmyaF
         w8lxtaK9m4eBstPsPziyDW4MMEINR2i6bZKw2VR8Nywt+7N2wccmxCzyOYwxgEh5g3ID
         VISo7IJPcOeg/hTG8rRmENnR8PyAlZEsH6feziAVRADhoq4uZpoHqSZ2BtER2eSUQXG3
         krBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i9S2rWNS;
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712131654; x=1712736454; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GVokH9vLit0JnzLAjXIqCCFqkh5uitEya9LZD8DbRQo=;
        b=fJsHNXDc5PLm4NCC8cFe9SYLrRlmA42GqZatqosKcCz83bsSKFvc3Apzq+R/OYcUNj
         vKuj1hiUTL4r+w3L4FlCjEfzFN6hjRKpmKB9+uYKzd7dwITqjuCWn7twTScowc6E6fLP
         Q7RxBtBx2JyLJFmO1grnm6tE5e8QU/dQRN/hi20VLnZah2Ex8WTIJ0K3r2odv3qDxcg+
         yJnMljkMZ4TA7Uc8/gumm289za0amWZhmIU9FRaLtkPOWBYg66nWZu9KXh8lesgHdlHl
         RWgZUvq27MG15Eb/yOcTHw7vFU2Jc/71ZCt+CV1xWRyAgqN4BOHP0AQIhONnsiqm4EwJ
         k52w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712131654; x=1712736454;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GVokH9vLit0JnzLAjXIqCCFqkh5uitEya9LZD8DbRQo=;
        b=fazRawn1Gg0Q/m8qLlr5ktdI/3/mtbdXfIyNhGkCq2y3gnbVoPTJ54/MEEWG547Y97
         qND8D/ftUmWsHUqcSHJ/v7bwxR1tOaTUekpxjA3yUrdjbFb1y2FbxyKgEwc+Bwc+cxcw
         cU2gcoXwU+CXP+1WxZUCK8tLX/Cj3s5k31p80zub7q+XpveVxAnYsOwCtagKquuxRidx
         gNp2cl6rXnQxKUrxJsQuCkd6iLMDmMakntXXmhBiTPoUlQdPDvZGwnXtkb+b3O4XG/Oe
         KwbpYTuoeLm0D3hWx+PKrGa+zTkz3mJgw+RYhLt3XY8lgJVC2jBiD6L7pQcmgB5Z4ikh
         j6jg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV72MYq36BKQLUBGblOmDcGf3Z3ipRrEzuMvEK3sJepEJcRf0SBo+Y0R6tJOjcs72ZLVDBW3VEU5YgbmjX22+ku/S6a9IwLSQ==
X-Gm-Message-State: AOJu0Yzz6jUK8caz6Bjen29pSncl1ShCByeASb+MXhEQgDMRWEFhn3qO
	X1+z7Ve1+0bdjfPQKEonXBDrM72nKh+RaqtT+i3Fq1BUKnQRxbha
X-Google-Smtp-Source: AGHT+IH/y740ylVSi6lFeBgX1jzfaPEC8eyaPmV8yokN/Pk9J7m58wLDSrGeK2caifPH3+xCQMjxuA==
X-Received: by 2002:a25:84c6:0:b0:dcc:8d09:c7c4 with SMTP id x6-20020a2584c6000000b00dcc8d09c7c4mr1810935ybm.7.1712131653906;
        Wed, 03 Apr 2024 01:07:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a027:0:b0:dcc:8ecd:49fe with SMTP id x36-20020a25a027000000b00dcc8ecd49fels734610ybh.0.-pod-prod-02-us;
 Wed, 03 Apr 2024 01:07:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPoQy4J+KzZvw4hkvEJAicdn333Aj9KF4WdlwZfyoieEZCQfVn+n6/BZ7RWg3LVKQ0oohdxK7Q0O3clBQDWBaCXZUwCQLN6OSkdQ==
X-Received: by 2002:a5b:6cd:0:b0:dcf:c7ef:e4e0 with SMTP id r13-20020a5b06cd000000b00dcfc7efe4e0mr1748772ybq.1.1712131652872;
        Wed, 03 Apr 2024 01:07:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712131652; cv=none;
        d=google.com; s=arc-20160816;
        b=tV6Os6WWOp6OHB0mAuGgGGFz/nm/zWexKcLK9HwkNEYxDaIRkcJhOaEAjKeuDhn5b1
         rnUzKCZfkI1sbZqULjhhaGiQRHAP6wk+kp9IlNYZUd2wK/Fdm9/FV4iZHwTrz5wmgSRk
         36jge3UYgHMkBuGG4GxN2iex6MXrg/9Yb6gJIu9VA6DrN3CieTxH9TNbQiSzzSFa5uTg
         vFnIqZ3M3OLbxmWnym0qUiGF8suEIevnvWvFK4I0P034y90LDmMz16a3nUj5W3MH673u
         BGvE5d30J4dmu4bOM1mngEPG8oBoaIvRLlVmvoTfDMflH9FnQYVKMnHyQrRz4hJJ5b4c
         Lfsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=zPQI3gKs/xYD8xNFhLrKzEKV+vfff/HWbqwJO21zJzM=;
        fh=+Cha03WazY+6q+yqqjwgFfJUCnejP3aPpYUiA2pdMoI=;
        b=jKSW+8eHmgl8YKMGMOtuwz/NtvDeFxALVtUjLeHlQBYpGmtt3rqCx5s6c5Bc+UWzru
         ZRWhqizxFl3faqQijrBEX/cflv3fqVdwm81MtLVKZvxdIn7YKsbjXuz0o/jPihtEWX22
         +QL2jNSHjjQQ0ZIjZa2mQ/yfAk5HpFE8BIrYTUkB6PUMgtzKOQ93gp3+b7UyqD/9bbbh
         brfR87N1mZB4wKx9Zd59DUiA3kyk8SzX7Cs2hj+oN/VILIUpOA35x4GDAPihHXQcyMvb
         3/sgLgUHMgV5GQ15x40OGMNcHw0RkkMAxN4d4Bt+rjchflJAlc0oPqNcoBPGTG68coJM
         G2lw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=i9S2rWNS;
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id s92-20020a25aa65000000b00dc657e7de95si903114ybi.0.2024.04.03.01.07.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Apr 2024 01:07:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id A376DCE210F;
	Wed,  3 Apr 2024 08:07:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9555FC433C7;
	Wed,  3 Apr 2024 08:07:08 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: linux-kernel@vger.kernel.org
Cc: Arnd Bergmann <arnd@arndb.de>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Damien Le Moal <dlemoal@kernel.org>,
	Jiri Kosina <jikos@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Corey Minyard <minyard@acm.org>,
	Peter Huewe <peterhuewe@gmx.de>,
	Jarkko Sakkinen <jarkko@kernel.org>,
	Tero Kristo <kristo@kernel.org>,
	Stephen Boyd <sboyd@kernel.org>,
	Ian Abbott <abbotti@mev.co.uk>,
	H Hartley Sweeten <hsweeten@visionengravers.com>,
	Srinivas Pandruvada <srinivas.pandruvada@linux.intel.com>,
	Len Brown <lenb@kernel.org>,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	John Allen <john.allen@amd.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Vinod Koul <vkoul@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Bjorn Andersson <andersson@kernel.org>,
	Moritz Fischer <mdf@kernel.org>,
	Liviu Dudau <liviu.dudau@arm.com>,
	Benjamin Tissoires <benjamin.tissoires@redhat.com>,
	Andi Shyti <andi.shyti@kernel.org>,
	Michael Hennerich <michael.hennerich@analog.com>,
	Peter Rosin <peda@axentia.se>,
	Lars-Peter Clausen <lars@metafoo.de>,
	Jonathan Cameron <jic23@kernel.org>,
	Dmitry Torokhov <dmitry.torokhov@gmail.com>,
	Markuss Broks <markuss.broks@gmail.com>,
	Alexandre Torgue <alexandre.torgue@foss.st.com>,
	Lee Jones <lee@kernel.org>,
	Jakub Kicinski <kuba@kernel.org>,
	Shyam Sundar S K <Shyam-sundar.S-k@amd.com>,
	Iyappan Subramanian <iyappan@os.amperecomputing.com>,
	Yisen Zhuang <yisen.zhuang@huawei.com>,
	Stanislaw Gruszka <stf_xl@wp.pl>,
	Kalle Valo <kvalo@kernel.org>,
	Sebastian Reichel <sre@kernel.org>,
	Tony Lindgren <tony@atomide.com>,
	Mark Brown <broonie@kernel.org>,
	Alexandre Belloni <alexandre.belloni@bootlin.com>,
	Xiang Chen <chenxiang66@hisilicon.com>,
	"Martin K. Petersen" <martin.petersen@oracle.com>,
	Neil Armstrong <neil.armstrong@linaro.org>,
	Heiko Stuebner <heiko@sntech.de>,
	Krzysztof Kozlowski <krzysztof.kozlowski@linaro.org>,
	Vaibhav Hiremath <hvaibhav.linux@gmail.com>,
	Alex Elder <elder@kernel.org>,
	Jiri Slaby <jirislaby@kernel.org>,
	Jacky Huang <ychuang3@nuvoton.com>,
	Helge Deller <deller@gmx.de>,
	Christoph Hellwig <hch@lst.de>,
	Robin Murphy <robin.murphy@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Kees Cook <keescook@chromium.org>,
	Trond Myklebust <trond.myklebust@hammerspace.com>,
	Anna Schumaker <anna@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Takashi Iwai <tiwai@suse.com>,
	linuxppc-dev@lists.ozlabs.org,
	linux-ide@vger.kernel.org,
	openipmi-developer@lists.sourceforge.net,
	linux-integrity@vger.kernel.org,
	linux-omap@vger.kernel.org,
	linux-clk@vger.kernel.org,
	linux-pm@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	dmaengine@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-arm-msm@vger.kernel.org,
	linux-fpga@vger.kernel.org,
	dri-devel@lists.freedesktop.org,
	linux-input@vger.kernel.org,
	linux-i2c@vger.kernel.org,
	linux-iio@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-arm-kernel@lists.infradead.org,
	netdev@vger.kernel.org,
	linux-leds@vger.kernel.org,
	linux-wireless@vger.kernel.org,
	linux-rtc@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	linux-spi@vger.kernel.org,
	linux-amlogic@lists.infradead.org,
	linux-rockchip@lists.infradead.org,
	linux-samsung-soc@vger.kernel.org,
	greybus-dev@lists.linaro.org,
	linux-staging@lists.linux.dev,
	linux-serial@vger.kernel.org,
	linux-usb@vger.kernel.org,
	linux-fbdev@vger.kernel.org,
	iommu@lists.linux.dev,
	linux-trace-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-nfs@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	alsa-devel@alsa-project.org,
	linux-sound@vger.kernel.org
Subject: [PATCH 00/34] address all -Wunused-const warnings
Date: Wed,  3 Apr 2024 10:06:18 +0200
Message-Id: <20240403080702.3509288-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=i9S2rWNS;       spf=pass
 (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted
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

Compilers traditionally warn for unused 'static' variables, but not
if they are constant. The reason here is a custom for C++ programmers
to define named constants as 'static const' variables in header files
instead of using macros or enums.

In W=1 builds, we get warnings only static const variables in C
files, but not in headers, which is a good compromise, but this still
produces warning output in at least 30 files. These warnings are
almost all harmless, but also trivial to fix, and there is no
good reason to warn only about the non-const variables being unused.

I've gone through all the files that I found using randconfig and
allmodconfig builds and created patches to avoid these warnings,
with the goal of retaining a clean build once the option is enabled
by default.

Unfortunately, there is one fairly large patch ("drivers: remove
incorrect of_match_ptr/ACPI_PTR annotations") that touches
34 individual drivers that all need the same one-line change.
If necessary, I can split it up by driver or by subsystem,
but at least for reviewing I would keep it as one piece for
the moment.

Please merge the individual patches through subsystem trees.
I expect that some of these will have to go through multiple
revisions before they are picked up, so anything that gets
applied early saves me from resending.

        Arnd

Arnd Bergmann (31):
  powerpc/fsl-soc: hide unused const variable
  ubsan: fix unused variable warning in test module
  platform: goldfish: remove ACPI_PTR() annotations
  i2c: pxa: hide unused icr_bits[] variable
  3c515: remove unused 'mtu' variable
  tracing: hide unused ftrace_event_id_fops
  Input: synaptics: hide unused smbus_pnp_ids[] array
  power: rt9455: hide unused rt9455_boost_voltage_values
  efi: sysfb: don't build when EFI is disabled
  clk: ti: dpll: fix incorrect #ifdef checks
  apm-emulation: hide an unused variable
  sisfb: hide unused variables
  dma/congiguous: avoid warning about unused size_bytes
  leds: apu: remove duplicate DMI lookup data
  iio: ad5755: hook up of_device_id lookup to platform driver
  greybus: arche-ctrl: move device table to its right location
  lib: checksum: hide unused expected_csum_ipv6_magic[]
  sunrpc: suppress warnings for unused procfs functions
  comedi: ni_atmio: avoid warning for unused device_ids[] table
  iwlegacy: don't warn for unused variables with DEBUG_FS=n
  drm/komeda: don't warn for unused debugfs files
  firmware: qcom_scm: mark qcom_scm_qseecom_allowlist as __maybe_unused
  crypto: ccp - drop platform ifdef checks
  usb: gadget: omap_udc: remove unused variable
  isdn: kcapi: don't build unused procfs code
  cpufreq: intel_pstate: hide unused intel_pstate_cpu_oob_ids[]
  net: xgbe: remove extraneous #ifdef checks
  Input: imagis - remove incorrect ifdef checks
  sata: mv: drop unnecessary #ifdef checks
  ASoC: remove incorrect of_match_ptr/ACPI_PTR annotations
  spi: remove incorrect of_match_ptr annotations
  drivers: remove incorrect of_match_ptr/ACPI_PTR annotations
  kbuild: always enable -Wunused-const-variable

Krzysztof Kozlowski (1):
  Input: stmpe-ts - mark OF related data as maybe unused

 arch/powerpc/sysdev/fsl_msi.c                 |  2 +
 drivers/ata/sata_mv.c                         | 64 +++++++++----------
 drivers/char/apm-emulation.c                  |  5 +-
 drivers/char/ipmi/ipmb_dev_int.c              |  2 +-
 drivers/char/tpm/tpm_ftpm_tee.c               |  2 +-
 drivers/clk/ti/dpll.c                         | 10 ++-
 drivers/comedi/drivers/ni_atmio.c             |  2 +-
 drivers/cpufreq/intel_pstate.c                |  2 +
 drivers/crypto/ccp/sp-platform.c              | 14 +---
 drivers/dma/img-mdc-dma.c                     |  2 +-
 drivers/firmware/efi/Makefile                 |  3 +-
 drivers/firmware/efi/sysfb_efi.c              |  2 -
 drivers/firmware/qcom/qcom_scm.c              |  2 +-
 drivers/fpga/versal-fpga.c                    |  2 +-
 .../gpu/drm/arm/display/komeda/komeda_dev.c   |  8 ---
 drivers/hid/hid-google-hammer.c               |  6 +-
 drivers/i2c/busses/i2c-pxa.c                  |  2 +-
 drivers/i2c/muxes/i2c-mux-ltc4306.c           |  2 +-
 drivers/i2c/muxes/i2c-mux-reg.c               |  2 +-
 drivers/iio/dac/ad5755.c                      |  1 +
 drivers/input/mouse/synaptics.c               |  2 +
 drivers/input/touchscreen/imagis.c            |  4 +-
 drivers/input/touchscreen/stmpe-ts.c          |  2 +-
 drivers/input/touchscreen/wdt87xx_i2c.c       |  2 +-
 drivers/isdn/capi/Makefile                    |  3 +-
 drivers/isdn/capi/kcapi.c                     |  7 +-
 drivers/leds/leds-apu.c                       |  3 +-
 drivers/mux/adg792a.c                         |  2 +-
 drivers/net/ethernet/3com/3c515.c             |  3 -
 drivers/net/ethernet/amd/xgbe/xgbe-platform.c |  8 ---
 drivers/net/ethernet/apm/xgene-v2/main.c      |  2 +-
 drivers/net/ethernet/hisilicon/hns_mdio.c     |  2 +-
 drivers/net/wireless/intel/iwlegacy/4965-rs.c | 15 +----
 drivers/net/wireless/intel/iwlegacy/common.h  |  2 -
 drivers/platform/goldfish/goldfish_pipe.c     |  2 +-
 drivers/power/supply/rt9455_charger.c         |  2 +
 drivers/regulator/pbias-regulator.c           |  2 +-
 drivers/regulator/twl-regulator.c             |  2 +-
 drivers/regulator/twl6030-regulator.c         |  2 +-
 drivers/rtc/rtc-fsl-ftm-alarm.c               |  2 +-
 drivers/scsi/hisi_sas/hisi_sas_v1_hw.c        |  2 +-
 drivers/scsi/hisi_sas/hisi_sas_v2_hw.c        |  2 +-
 drivers/spi/spi-armada-3700.c                 |  2 +-
 drivers/spi/spi-img-spfi.c                    |  2 +-
 drivers/spi/spi-meson-spicc.c                 |  2 +-
 drivers/spi/spi-meson-spifc.c                 |  2 +-
 drivers/spi/spi-orion.c                       |  2 +-
 drivers/spi/spi-pic32-sqi.c                   |  2 +-
 drivers/spi/spi-pic32.c                       |  2 +-
 drivers/spi/spi-rockchip.c                    |  2 +-
 drivers/spi/spi-s3c64xx.c                     |  2 +-
 drivers/spi/spi-st-ssc4.c                     |  2 +-
 drivers/staging/greybus/arche-apb-ctrl.c      |  1 +
 drivers/staging/greybus/arche-platform.c      |  9 +--
 drivers/staging/pi433/pi433_if.c              |  2 +-
 drivers/tty/serial/amba-pl011.c               |  6 +-
 drivers/tty/serial/ma35d1_serial.c            |  2 +-
 drivers/usb/gadget/udc/omap_udc.c             | 10 +--
 drivers/video/fbdev/sis/init301.c             |  3 +-
 kernel/dma/contiguous.c                       |  2 +-
 kernel/trace/trace_events.c                   |  4 ++
 lib/checksum_kunit.c                          |  2 +
 lib/test_ubsan.c                              |  2 +-
 net/sunrpc/cache.c                            | 10 +--
 scripts/Makefile.extrawarn                    |  1 -
 sound/soc/atmel/sam9x5_wm8731.c               |  2 +-
 sound/soc/codecs/rt5514-spi.c                 |  2 +-
 sound/soc/qcom/lpass-sc7280.c                 |  2 +-
 sound/soc/samsung/aries_wm8994.c              |  2 +-
 69 files changed, 121 insertions(+), 169 deletions(-)

-- 
2.39.2

Cc: Michael Ellerman <mpe@ellerman.id.au>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Damien Le Moal <dlemoal@kernel.org>
Cc: Jiri Kosina <jikos@kernel.org>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Corey Minyard <minyard@acm.org>
Cc: Peter Huewe <peterhuewe@gmx.de>
Cc: Jarkko Sakkinen <jarkko@kernel.org>
Cc: Tero Kristo <kristo@kernel.org>
Cc: Stephen Boyd <sboyd@kernel.org>
Cc: Ian Abbott <abbotti@mev.co.uk>
Cc: H Hartley Sweeten <hsweeten@visionengravers.com>
Cc: Srinivas Pandruvada <srinivas.pandruvada@linux.intel.com>
Cc: Len Brown <lenb@kernel.org>
Cc: "Rafael J. Wysocki" <rafael@kernel.org>
Cc: John Allen <john.allen@amd.com>
Cc: Herbert Xu <herbert@gondor.apana.org.au>
Cc: Vinod Koul <vkoul@kernel.org>
Cc: Ard Biesheuvel <ardb@kernel.org>
Cc: Bjorn Andersson <andersson@kernel.org>
Cc: Moritz Fischer <mdf@kernel.org>
Cc: Liviu Dudau <liviu.dudau@arm.com>
Cc: Benjamin Tissoires <benjamin.tissoires@redhat.com>
Cc: Andi Shyti <andi.shyti@kernel.org>
Cc: Michael Hennerich <michael.hennerich@analog.com>
Cc: Peter Rosin <peda@axentia.se>
Cc: Lars-Peter Clausen <lars@metafoo.de>
Cc: Jonathan Cameron <jic23@kernel.org>
Cc: Dmitry Torokhov <dmitry.torokhov@gmail.com>
Cc: Markuss Broks <markuss.broks@gmail.com>
Cc: Alexandre Torgue <alexandre.torgue@foss.st.com>
Cc: Lee Jones <lee@kernel.org>
Cc: Jakub Kicinski <kuba@kernel.org>
Cc: Shyam Sundar S K <Shyam-sundar.S-k@amd.com>
Cc: Iyappan Subramanian <iyappan@os.amperecomputing.com>
Cc: Yisen Zhuang <yisen.zhuang@huawei.com>
Cc: Stanislaw Gruszka <stf_xl@wp.pl>
Cc: Kalle Valo <kvalo@kernel.org>
Cc: Sebastian Reichel <sre@kernel.org>
Cc: Tony Lindgren <tony@atomide.com>
Cc: Mark Brown <broonie@kernel.org>
Cc: Alexandre Belloni <alexandre.belloni@bootlin.com>
Cc: Xiang Chen <chenxiang66@hisilicon.com>
Cc: "Martin K. Petersen" <martin.petersen@oracle.com>
Cc: Neil Armstrong <neil.armstrong@linaro.org>
Cc: Heiko Stuebner <heiko@sntech.de>
Cc: Krzysztof Kozlowski <krzysztof.kozlowski@linaro.org>
Cc: Vaibhav Hiremath <hvaibhav.linux@gmail.com>
Cc: Alex Elder <elder@kernel.org>
Cc: Jiri Slaby <jirislaby@kernel.org>
Cc: Jacky Huang <ychuang3@nuvoton.com>
Cc: Helge Deller <deller@gmx.de>
Cc: Christoph Hellwig <hch@lst.de>
Cc: Robin Murphy <robin.murphy@arm.com>
Cc: Steven Rostedt <rostedt@goodmis.org>
Cc: Masami Hiramatsu <mhiramat@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>
Cc: Trond Myklebust <trond.myklebust@hammerspace.com>
Cc: Anna Schumaker <anna@kernel.org>
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Takashi Iwai <tiwai@suse.com>
Cc: linuxppc-dev@lists.ozlabs.org
Cc: linux-kernel@vger.kernel.org
Cc: linux-ide@vger.kernel.org
Cc: openipmi-developer@lists.sourceforge.net
Cc: linux-integrity@vger.kernel.org
Cc: linux-omap@vger.kernel.org
Cc: linux-clk@vger.kernel.org
Cc: linux-pm@vger.kernel.org
Cc: linux-crypto@vger.kernel.org
Cc: dmaengine@vger.kernel.org
Cc: linux-efi@vger.kernel.org
Cc: linux-arm-msm@vger.kernel.org
Cc: linux-fpga@vger.kernel.org
Cc: dri-devel@lists.freedesktop.org
Cc: linux-input@vger.kernel.org
Cc: linux-i2c@vger.kernel.org
Cc: linux-iio@vger.kernel.org
Cc: linux-stm32@st-md-mailman.stormreply.com
Cc: linux-arm-kernel@lists.infradead.org
Cc: netdev@vger.kernel.org
Cc: linux-leds@vger.kernel.org
Cc: linux-wireless@vger.kernel.org
Cc: linux-rtc@vger.kernel.org
Cc: linux-scsi@vger.kernel.org
Cc: linux-spi@vger.kernel.org
Cc: linux-amlogic@lists.infradead.org
Cc: linux-rockchip@lists.infradead.org
Cc: linux-samsung-soc@vger.kernel.org
Cc: greybus-dev@lists.linaro.org
Cc: linux-staging@lists.linux.dev
Cc: linux-serial@vger.kernel.org
Cc: linux-usb@vger.kernel.org
Cc: linux-fbdev@vger.kernel.org
Cc: iommu@lists.linux.dev
Cc: linux-trace-kernel@vger.kernel.org
Cc: kasan-dev@googlegroups.com
Cc: linux-hardening@vger.kernel.org
Cc: linux-nfs@vger.kernel.org
Cc: linux-kbuild@vger.kernel.org
Cc: alsa-devel@alsa-project.org
Cc: linux-sound@vger.kernel.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240403080702.3509288-1-arnd%40kernel.org.
