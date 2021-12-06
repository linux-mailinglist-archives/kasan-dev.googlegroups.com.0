Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBWOZW6GQMGQEXMALTFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F4E1469493
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 11:58:34 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id m1-20020ac24281000000b004162863a2fcsf3693863lfh.14
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 02:58:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638788314; cv=pass;
        d=google.com; s=arc-20160816;
        b=sPxKSZvEm/gRat6H0FvaIQBZcBKiAgW0nNsOyJGXfwnadJuSlHl+PAQHCaeSUdfKq0
         ArfCF0I8dtBvkVSwYbDqY9v2eivnJvsImInsPPAcCVgMh27c3Fv9idT7H+dl3XHFQSfa
         sDhKgfSu1nKumosawjEnfBkl+Rcku3cXZp1Ml9wryer42PERb22O/lK7gWP2ld806ZdW
         6JFCjA+CDxtgc1+KamXYT7ayihTKJE8X91gTZozvy2oBWv5tXxsQ+dpkwDRRqlvPQ8uW
         X9d7J1fPDy7oN21Q1VvXpwZ/36YhLqaP8IcbxL+X3xKxjoBrj+Ro2+9eZ3WvodCaxWvg
         V97A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=htXaKQU5D9wmxSXGNaOrOdhI7hT5ZCsAuoxRkR6aar8=;
        b=ol600CKViEkjqGTunBA4bpJpvPRXWXk3X8Xf3TmZvWoG8kTqyKnTcyzLSegHi5O2P0
         UlOGAoeQs2Kxt2lnOluAf2Pt7j7Xg5mlymQAifW3GSWc6X+BXLlre3H7EQ6tkCHXKkOb
         tD29BuOr+HuS2jGg+olVv0lQQqn4FnxJ03JUthj4HO9qLKnEoQi52HD7vzkIqOtmWuxE
         cwgZHJgcl+clta18CsQukzgrxWlS3gCoVMlDKzrFMXM5/4Z10xyRz0Z5h2JomUh/6byc
         OffR72xIda69VOkf2MZyBGvPIKimBI+JYhsp350wYZo0za0cI9iD0vB64WGnEinTvGtH
         OHzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=cvHdqAoz;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=htXaKQU5D9wmxSXGNaOrOdhI7hT5ZCsAuoxRkR6aar8=;
        b=gLTOhFZgVMGSkoivMOZyRYUYqSnnW5e+q6eFXp9mzogfcp2UuKod38N46YaRqNsgiU
         vaMW4oOwBnIihryoL5qrcd8XQT8WbhPFeoOmIbXrzs+kFqKj9ewsGEhqm+M88KoOPUuG
         iXBejkDTJYCttTIaZWgTGNs/ih16BsJ8BP4nBuSJj9JggHtnHulxKspxbI+o0rCFCaz4
         Aemytq9OFLbI2dGoLX/81frZe6MgfmbyxejpuCAxhr2a5Z4R4L33mxLgc7R1TiV2CeW8
         B6TpS93s6eR3M+vqeu4AW4U/Ieqhaj4rfzO/AMTVSKnJnSh0wG5p/N6IE1r8EBWlDGyT
         DByA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=htXaKQU5D9wmxSXGNaOrOdhI7hT5ZCsAuoxRkR6aar8=;
        b=3VNRa3s4SQoXbJ8WloByrReKws7LoA9C7/p5hT68dM+oJDqNo7GFgI6tSKhgAY/hAI
         MNrlWylTLXsTUYJLDAU/eMRAl9UrlVE04sgRupiFWYyWgjiZVhvQtfVudCz7N2L2Kgbn
         MpCaHvcEkGl4GtWUuv4/pemXRDAA2rJzctOVB8ckE3tDnBAtejCfDqfp3sGUmMhl5O4u
         GCePy+/kbMK2+zCNYweo5oFffh3vbDepXWMLN91opHZVsOuGy3MRBBABdosgsTYNFa7A
         NqhRFupDmn5xbvDJoB/gFpIP03hinVTjSxxJRNrs7Fl0emMY1PkhRE5UQ6w8EhhwaPmC
         wRvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Fb+z5P6NrJbkh8bLbL30cuvMD/yT+Nbm/Ilri8w5pqsw0rJIy
	tV7/KZZxBuWJqrcXOksQHVI=
X-Google-Smtp-Source: ABdhPJyyegYLLKWWi2Uhxo3+zR6PWjZN50Ox/FLxkzCDzUlndVqLBUymf9l+HbDoDmdoidNn6UENIQ==
X-Received: by 2002:a05:6512:11cb:: with SMTP id h11mr35758505lfr.297.1638788313973;
        Mon, 06 Dec 2021 02:58:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8611:: with SMTP id a17ls2502406lji.1.gmail; Mon, 06 Dec
 2021 02:58:33 -0800 (PST)
X-Received: by 2002:a2e:b0c5:: with SMTP id g5mr34418889ljl.381.1638788313039;
        Mon, 06 Dec 2021 02:58:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638788313; cv=none;
        d=google.com; s=arc-20160816;
        b=upeVRMM/QQ1hRbpU5EyY9tF3lqaLUk2+f7h2SSnOU1eptt2log1acVpogbjXmaZBFJ
         5fzund/hSFRp9/ar4x12BZ8ohbCkz6r/UA0oAmJlNxC9WumVEnPy0vOCDzq80be2AqdN
         orInMjdU9FfgZFIXRng0uPrXnYDzdBWnQOcp6v9P9b6SMo1rdU/BSP2+K2QQ0NHA55CT
         oxnZLImgRdg7tCRbEb5xWcDWg8Qf+yJxs7s2hCZUnki//ESXSmhUMBvnEAcdylA8+KRH
         HE6RrzgubtBLar0Sg3sEuNGijjQsX9CLXxbhZiyD/imaTaYqm+BxDyquD3cwUPMCqVjU
         NfOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vaFAezChlajkTZ7fI5kVmIBThbHyfEUEZ5Atc7Q1k0c=;
        b=yHyhVKgMVC5fTXsxnGVnazWiZ9BaU8mBCBcRMOkP0u+76wRG15w1gSrJae2ljHqecM
         s7GwcM15lkMhoL4uRN6CkZO/K/oYkfqW8K1fGX5/pVwYrjuNoZUeyWhFq3mwj4DaehKz
         rtWVxZfIz9oHnxLugGCxwKunO0URp5x/RPvYjNJ7d0GpTY1VlCpy1uwy0L6Zlzaitic2
         jEJ4+1rAHSTJd1ompL1UFQOOW/etD9R/KKWMwQDQ03b3pGub5nKWJ2B9Emxs4viSic6O
         PbGCM44Saxa9EGeh+AS95ClwJ3i6PYB22lnb+IzIdYel05FUpSDFXfsKpzA6vf68c8M/
         mQcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=cvHdqAoz;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id u19si696154ljl.5.2021.12.06.02.58.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:58:32 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com [209.85.128.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 2E4353F1C0
	for <kasan-dev@googlegroups.com>; Mon,  6 Dec 2021 10:58:32 +0000 (UTC)
Received: by mail-wm1-f72.google.com with SMTP id 201-20020a1c04d2000000b003335bf8075fso5954912wme.0
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 02:58:32 -0800 (PST)
X-Received: by 2002:a5d:4c87:: with SMTP id z7mr42470493wrs.108.1638788310552;
        Mon, 06 Dec 2021 02:58:30 -0800 (PST)
X-Received: by 2002:a5d:4c87:: with SMTP id z7mr42470463wrs.108.1638788310400;
        Mon, 06 Dec 2021 02:58:30 -0800 (PST)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id p27sm10378487wmi.28.2021.12.06.02.58.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:58:30 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@rivosinc.com>,
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
	panqinglin2020@iscas.ac.cn,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v3 11/13] Documentation: riscv: Add sv48 description to VM layout
Date: Mon,  6 Dec 2021 11:46:55 +0100
Message-Id: <20211206104657.433304-12-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=cvHdqAoz;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
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
index 1bd687b97104..5b36e45fef60 100644
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
+   ffff8d7ffee00000 |  -114.5 TB | ffff8d7ffeffffff |    2 MB | fixmap
+   ffff8d7fff000000 |  -114.5 TB | ffff8d7fffffffff |   16 MB | PCI io
+   ffff8d8000000000 |  -114.5 TB | ffff8f7fffffffff |    2 TB | vmemmap
+   ffff8f8000000000 |  -112.5 TB | ffffaf7fffffffff |   32 TB | vmalloc/ioremap space
+   ffffaf8000000000 |  -80.5  TB | ffffef7fffffffff |   64 TB | direct mapping of all physical memory
+   ffffef8000000000 |  -16.5  TB | fffffffeffffffff | 16.5 TB | kasan
+  __________________|____________|__________________|_________|____________________________________________________________
+                                                              |
+                                                              | Identical layout to the 39-bit one from here on:
+  ____________________________________________________________|____________________________________________________________
+                    |            |                  |         |
+   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules, BPF
+   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel
+  __________________|____________|__________________|_________|____________________________________________________________
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206104657.433304-12-alexandre.ghiti%40canonical.com.
