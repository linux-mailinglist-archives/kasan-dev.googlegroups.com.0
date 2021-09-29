Return-Path: <kasan-dev+bncBDQ7NGWH7YJRB3P62GFAMGQEDDMHH4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CDD641C7A8
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 16:59:58 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id z137-20020a1c7e8f000000b0030cd1800d86sf1350901wmc.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 07:59:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632927598; cv=pass;
        d=google.com; s=arc-20160816;
        b=zEyQ3rHRB34VZkorVZTVGupkah81wKdrMZNQdXzyqgMugKEUsMomGriKPKEeLnlugQ
         xKRR7DzpHkeoK5yG0tvfKSFryuSvLnUfSlMawJaZyQrwPCodPhzODYRs6vphcd4u9Z/x
         C2fIAn2t1B9W9aVIlq3S4dyappDpYIseNiGqXHBAlE9ZqYi1YnupQaNW+uelXeNA8KpC
         tDKVDFOIyk14r+jGr/TqMBfMGk1ienMw8h8RcOjWzavP+hR/WpWmsF/W79GtE6nzh+Ri
         lP2VMPpgvdsa88LxlAsCT+MAle9yUWHEav4fNYOpuxX2X+u98ptS7kDYeXkeaIygo9yB
         dixw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jFfKBedrxqDA8dyh9qYTqtUFjOHQ+Cxz7HT5gfzKxWQ=;
        b=VxQsvBffxrrQn963BTKIeSG2gpyr2E+lYpDkyzn3sqPb0golu0VOBxro5ZdRH6p85F
         FGDPFL5lAT4xHKCtGcuMsalEfmJVN10vLsi4gLqeor+qpaHopQh/FogpLvrlC/oLdnmY
         H3UBkUtacSspHK5nddU5zApKMhQe6ZmeNrPVZpSNNN/Ht7x6bTRVNx/Fx9mE252xYfMJ
         eSGnbS9UdTuLbtkIAa4883lj9sdEGWAEWQo4Fx5cS7IF4P8+v8hoIc4woRTNFAf3PR8r
         wJnVeNpXanOWDhIRoCY1+aDS292kOe2p1g3dTnWtRuSAYUCqq9xsNFT+jjEX/IcYqnfU
         7Zag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b="e/NHVun2";
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jFfKBedrxqDA8dyh9qYTqtUFjOHQ+Cxz7HT5gfzKxWQ=;
        b=T+JdMJyqURPYDoQNSknFgNqo9+MOmVThHxpr4A1U2KigaIpArmw9M+Ku/5gxmx5+AM
         HDDyV/Y7EX3t3Ds1Rg6Ul7YJXsbbEiZo0a5Klj8l1sidZm8mC2ln5wtmvtuCl6rAMDGe
         HwpfGMuvi6UfJNmD2BKJPSq22LuHWPm9qR3Mykz0tLcfz+du9pd4NnwsJg6VL6OUXLXv
         C+iabr6PZrcsVSM65CNDvvvs/lC6xX0/4to1LAEMASdDsUWMWgPGt+cg4MiEqzAVtU98
         m1xIpU7ufP1pVZqnu+XTCSqvP3yTtJ/S4bhrUHrK0zG1R2OLgckEhmN2mxbembeoelgd
         oQuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jFfKBedrxqDA8dyh9qYTqtUFjOHQ+Cxz7HT5gfzKxWQ=;
        b=ec0NnscSYExOnOM7Xmfpy/iW1njTbUG2//HjSYuTGyLVZqNxP6zep9Zs2hGyg76Z0M
         meEWT8+lzgbxzKl+FeEyvmbLijSBQgOj/NhfgIxdqFPOOQ1PJ21nd3YQg+pNJvKPfEz5
         Xrnuy2i4ba3yS8Vz8ZFlTKEVFxtEmG2scEaVc0kFIjvh3uOZOLMpDCDc05DzRgbOESx6
         4GFqCtkrqVTCvMu6kFTNZ/TmdWcPZXx/9ntTvLw6uehi77bCce9p2Yh76dCs8U6Sr0FB
         OQdF243CwIQDOTNWZbo4sivbwFoH39o4ytwZ9kbLTh2CdzsomBr//j7n/j47CeODawXA
         uFbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530cPuZU414LoM09Li6v/e/9R0gcqi++qhG/XRI9kTQRtNME8Ey5
	5mchH7hEJ+lDnwq3vDaUrag=
X-Google-Smtp-Source: ABdhPJwpsVuyyWGfi8q/tIaNYY4maXvvnjETgWoWwiaTLOB1Fi+djQi9hDWuUS7e+K4fqNbnWHcPfg==
X-Received: by 2002:adf:ea8e:: with SMTP id s14mr373300wrm.168.1632927598117;
        Wed, 29 Sep 2021 07:59:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c7ca:: with SMTP id z10ls3354753wmk.0.canary-gmail; Wed,
 29 Sep 2021 07:59:57 -0700 (PDT)
X-Received: by 2002:a1c:f405:: with SMTP id z5mr10617739wma.33.1632927597279;
        Wed, 29 Sep 2021 07:59:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632927597; cv=none;
        d=google.com; s=arc-20160816;
        b=lTMilQDgG0MJ852f01TkqFP9YH8vrCV/3q4RcW/Sm+Eww1h9RTVxN/3ML8lRgN+J73
         BfQ2zNt2ejZjZ4YXoddfBgSDqbeBUuzkIvQnEgx9YkWx57463JCV+rSwJquiwgyHJW4w
         fx8E3PW35Jhprfzmhzd85iIcXZ7SLsWwuUZVbssj08F4ainru5EKr1C77dzLp34omQoK
         wOSx6PgoUMIcgsFkfby/2KvjCGmhW1HXgkB9Bf4OtCV109f+5Q0Hs1q6nlcOwD+3wZB6
         4QkCwc0ZtmUyGQk5ymmkNRCkGnMW7EvzzaZHMOZWgPwRM/qG9PMjaNmVTqpEskAX7Wic
         k+og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3cu0sC+0/nYKnIJicRvpKscpuwOhF+7jr6vCCwWJtCY=;
        b=SnY3D3+eeavDNie+Vose2MFjfr8c0W2e19qXz4WAxRtnfTsGYiUI+InMNNYmxad9c9
         y+5vcJ4004N6flfdwgqiSP0O+e7vDxfczF2TAbqf/KseB39uXrCRoHpWFmExluUplBID
         XMXxiYelPGjxEiTnttD8xukKuMqrjh1tUGTJEgnrJq3x2QEat8k2+DmPMFFVnkMCEBa4
         WaBOGgS8xcN2MBrkl51L+cCii/Gdth4IYA3DO/YLBUNW9x9NCQXgo6/gWPZcvNTA/+MY
         7Vh8zcPSZsvixeTYXoXoUNQyjgroxaw1tWJgfBnUyPvSs0B6J8N/zayC9KZsG0ag0PdT
         MUHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b="e/NHVun2";
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id e2si7648wrj.4.2021.09.29.07.59.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:59:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-lf1-f70.google.com (mail-lf1-f70.google.com [209.85.167.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id EDCA940603
	for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 14:59:56 +0000 (UTC)
Received: by mail-lf1-f70.google.com with SMTP id i40-20020a0565123e2800b003f53da59009so2626410lfv.16
        for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 07:59:56 -0700 (PDT)
X-Received: by 2002:a5d:6d81:: with SMTP id l1mr340933wrs.404.1632927585422;
        Wed, 29 Sep 2021 07:59:45 -0700 (PDT)
X-Received: by 2002:a5d:6d81:: with SMTP id l1mr340890wrs.404.1632927585227;
        Wed, 29 Sep 2021 07:59:45 -0700 (PDT)
Received: from alex.home (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id l16sm81418wmj.33.2021.09.29.07.59.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:59:44 -0700 (PDT)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@wdc.com>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Kees Cook <keescook@chromium.org>,
	Guo Ren <guoren@linux.alibaba.com>,
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
	Mayuresh Chitale <mchitale@ventanamicro.com>,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v2 08/10] Documentation: riscv: Add sv48 description to VM layout
Date: Wed, 29 Sep 2021 16:51:11 +0200
Message-Id: <20210929145113.1935778-9-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
References: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b="e/NHVun2";       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

sv48 was just introduced, so add its virtual memory layout to the
documentation.

Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 Documentation/riscv/vm-layout.rst | 36 +++++++++++++++++++++++++++++++
 1 file changed, 36 insertions(+)

diff --git a/Documentation/riscv/vm-layout.rst b/Documentation/riscv/vm-layout.rst
index b7f98930d38d..f10128e0a95f 100644
--- a/Documentation/riscv/vm-layout.rst
+++ b/Documentation/riscv/vm-layout.rst
@@ -61,3 +61,39 @@ RISC-V Linux Kernel SV39
    ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules, BPF
    ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel
   __________________|____________|__________________|_________|____________________________________________________________
+
+
+RISC-V Linux Kernel SV48
+------------------------
+
+::
+
+ ========================================================================================================================
+      Start addr    |   Offset   |     End addr     |  Size   | VM area description
+ ========================================================================================================================
+                    |            |                  |         |
+   0000000000000000 |    0       | 00007fffffffffff |  128 TB | user-space virtual memory, different per mm
+  __________________|____________|__________________|_________|___________________________________________________________
+                    |            |                  |         |
+   0000800000000000 | +128    TB | ffff7fffffffffff | ~16M TB | ... huge, almost 64 bits wide hole of non-canonical
+                    |            |                  |         | virtual memory addresses up to the -128 TB
+                    |            |                  |         | starting offset of kernel mappings.
+  __________________|____________|__________________|_________|___________________________________________________________
+                                                              |
+                                                              | Kernel-space virtual memory, shared between all processes:
+  ____________________________________________________________|___________________________________________________________
+                    |            |                  |         |
+   ffff800000000000 | -128    TB | ffff8fffffffffff |   16 TB | kasan
+   ffff9dfffee00000 |  -94    TB | ffff9dfffeffffff |    2 MB | fixmap
+   ffff9dffff000000 |  -94    TB | ffff9dffffffffff |   16 MB | PCI io
+   ffff9e0000000000 |  -94    TB | ffff9fffffffffff |    2 TB | vmemmap
+   ffffa00000000000 |  -92    TB | ffffbfffffffffff |   32 TB | vmalloc/ioremap space
+   ffffc00000000000 |  -64    TB | fffffffeffffffff |   64 TB | direct mapping of all physical memory
+  __________________|____________|__________________|_________|____________________________________________________________
+                                                              |
+                                                              | Identical layout to the 39-bit one from here on:
+  ____________________________________________________________|____________________________________________________________
+                    |            |                  |         |
+   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules, BPF
+   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel
+  __________________|____________|__________________|_________|____________________________________________________________
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210929145113.1935778-9-alexandre.ghiti%40canonical.com.
