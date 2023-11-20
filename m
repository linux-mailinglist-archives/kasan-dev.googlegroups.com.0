Return-Path: <kasan-dev+bncBDXYDPH3S4OBBQWN52VAMGQE4KRUTMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 14EEE7F1C78
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:44 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2c50255b905sf45301411fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505283; cv=pass;
        d=google.com; s=arc-20160816;
        b=GsbCmeVYZuZ7ZIAD1AL66TQb0EG3ztS51WbbwCKwt8+x54HLK0fk3q5W1OXAbpf/FU
         fWkpl4kkWdRfGkBPM+QfzV8qFZc1u3cDQiWkkehncfXw64tcnmitNeJ+3NHUOgu3rNc8
         MNQZMAPUkfKb1HAv/ufIL1kwehuoVJkYo1n1rIz8EiXbo36XH6vijS09e7PTP4LTjF+C
         dJnrhB3I8P5WXEkyIRvFJf7hEdYm6SNCfMdNMNVL2y6JrqUv+2IbkLX53zrgNX42062f
         513WF5eECuWosaAKjEQ3D9TEIcsWCICA+r8srPRv2HCa+uSmwzNlA/CSuw5cCf7z+rUS
         hV+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=hEhAJt2+x4+kWZk/g8GIK9BVidKGXDTvYh6lWZTPc0o=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=mURvWubmT7S6iNp0Hx8r0yAhuyi2joE5z3NRy3fhjFMANDjtd84tJN/5qIMSqixDho
         38n35+rxfDbpYkArsMYFTd0EKOP0TFBVpX+u4n4Ds/LGQPcS1p/ntXhMfiI4NKLiKK9L
         3EvhnHlRFRDatnCwblVBMx3jIe7JHTvv4wyAinhLoy6DFuS0qlwpGiTNbh482I5GgkXa
         mMw7kL0ktgNLX7gza07VNp25+aE21yxHbpOhn+ZndJ5fJW7hFXL3+fzDGXhgmIupo0V+
         gL48WnKFS0dMsuFKBkBnF7ACx6llY4hske+RlYSC0QVk4iL37QB8lmIj0fDcTjEJqwTd
         QJ7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TRzQJ1N7;
       dkim=neutral (no key) header.i=@suse.cz header.b=OzF+kCJ9;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505283; x=1701110083; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hEhAJt2+x4+kWZk/g8GIK9BVidKGXDTvYh6lWZTPc0o=;
        b=q3K6y+uQ/mKDVaTBJKOt9kYof01Ez3DmewQHelRK8khtNwSFSW5AarZMAHltaV+aJy
         3G8xHN5ycr7ff6GEDEE1EYmOGFZjQv65eCUDw3KPE0esuSAwvpZsG6JSvfMMKEtNqslT
         4ShFERVMpfNC4PVi5f6ak5Vh7nvf35zmhtWrrCiY0EDUiEw9whYmq4ozsUFEHQrxuay/
         v5KQNH4O78UGUK44Be8PV2VGO5upuWcV042vd00tGaLsOC/ThKvLVMBgn1nwJWnGZyCE
         JWMHQCFl8DHpiraeqKl0Bgq6cFp7oX7czXbJ5sLkLUf0kHzHhqdI+KEdPZFIHqt96S7O
         n83A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505283; x=1701110083;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hEhAJt2+x4+kWZk/g8GIK9BVidKGXDTvYh6lWZTPc0o=;
        b=eUNhBV8sfZKL9SopzJQNOnRjhaBkbGEqsBYMj8nLV1Jz3jNWTTp22a4JtGasi0y10t
         A34m3r3jWZXA8pKYzZHNsdvbUm8sByjGwt9zwDvb7O/mjMS0FXFBBH7E7C3gJJlN9qr8
         H/a+USAbrnLynx9ZBSd0t5UzGAIPNNk7cWO7IvPlVP9oyDF2QMcU75b72O3dIejXFOzk
         L0UVAfK85LldFzhL7NRsXAb8dll1BjWECplQHoLhvD4ey9c8mtJESwNC2FkJbAnMXmZG
         8AY2fVUK8KvG+i4s8AJZYxP5sbSEGDuqsHagI27jCASwsuJjWmGXTmOpOH5drxRkgSsA
         dSsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz5DSR45FIeyFv1oeCWutznGPQgUI1IR6pDqd2DbgGgpl3JbOSK
	MOCO4DzIYq12/7PLL/UGQ5g=
X-Google-Smtp-Source: AGHT+IE6WyVR1BfBJ1ZjQVF5H+sXowIZbPZEwfZUhMvxPaHGoxrBbOPH4EgfS7lHcjNJ804b7QSzLQ==
X-Received: by 2002:a2e:9814:0:b0:2b9:3684:165 with SMTP id a20-20020a2e9814000000b002b936840165mr5513489ljj.8.1700505282870;
        Mon, 20 Nov 2023 10:34:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:88d2:0:b0:2c8:80e3:b5e with SMTP id a18-20020a2e88d2000000b002c880e30b5els713886ljk.1.-pod-prod-07-eu;
 Mon, 20 Nov 2023 10:34:41 -0800 (PST)
X-Received: by 2002:a2e:8e23:0:b0:2bd:19c5:3950 with SMTP id r3-20020a2e8e23000000b002bd19c53950mr5056892ljk.33.1700505280737;
        Mon, 20 Nov 2023 10:34:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505280; cv=none;
        d=google.com; s=arc-20160816;
        b=ESdZvGkXT0DXl8O+u13/tWfMQLNC5yBerTINHKFobgY5Ja3wXkPmbtHmoovDupzD83
         wBm3MUUZYH2Mf0WqFyybsLG346FnI9X2Mm8uLmmh3SmS/KX7zZ+/v1ejEZ7v+W0zryjv
         +R4M8gsjUvRYGul1shO+lTM0gRLYtE/d6jHuLySZ9gCR6E4xds6FcFMXKQ6C3/hL/KHq
         KjYIN9z+mw02pxQOkPNguO51nChXEN7E1wV8283FRAJbcA0aAcUitIEL5iIHZYMnrVWR
         HnsNeBOFw06JYJfUdC0mD66As03yYm6pKgeXtgP42OWv95p4U3BMurif1Q5YnL5eoOqM
         9C5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=C3PvyHnt/pjNnb1ooQtn9ytwbQP6EaDR9ZNAzWepmxc=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=ouNMacTdIOrYDZ9FO8XCENIuCl7K0sdkH7y1r/sGXoVOtIbdC3nUO9jN3CcR3XPiXm
         p8Sq5Ciw/iYiXmsCDh45cpYOXXyjJLc5ewBZnaUCzGkt6VMsdkLynONXbYNLe2SWMauu
         vZBDs1e7ymYne8hROyQchl9xUovHnVo30oYNksEx43vhTail3aNPUATu+nx/SmYPz2Hh
         JArIpnQgWZX8Y7KFg963tkaqXhnxxeXwXKRbGSgUfujgi3nbyyp725RDnaWdCfa5iBQk
         EKmdt6xVZTXvN0aYZAMEYoeQDbKtDzJk5sxkPHTMAEUKLH0EQr5epDAFzGdYEZtlUBkw
         8w3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=TRzQJ1N7;
       dkim=neutral (no key) header.i=@suse.cz header.b=OzF+kCJ9;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id bg19-20020a05600c3c9300b00407c8777ecasi460516wmb.0.2023.11.20.10.34.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:40 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0E43421905;
	Mon, 20 Nov 2023 18:34:40 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id BDB5C139E9;
	Mon, 20 Nov 2023 18:34:39 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id qMHWLb+mW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:39 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:13 +0100
Subject: [PATCH v2 02/21] mm/slab: remove CONFIG_SLAB from all Kconfig and
 Makefile
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-2-9c9c70177183@suse.cz>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
In-Reply-To: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
To: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, 
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
 linux-hardening@vger.kernel.org, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Level: *
X-Spam-Score: 1.30
X-Spamd-Result: default: False [1.30 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 REPLY(-4.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 R_RATELIMIT(0.00)[to_ip_from(RL563rtnmcmc9sawm86hmgtctc)];
	 BAYES_SPAM(5.10)[99.99%];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[24];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,linux.dev,google.com,arm.com,cmpxchg.org,kernel.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com,suse.cz];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=TRzQJ1N7;       dkim=neutral
 (no key) header.i=@suse.cz header.b=OzF+kCJ9;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Remove CONFIG_SLAB, CONFIG_DEBUG_SLAB, CONFIG_SLAB_DEPRECATED and
everything in Kconfig files and mm/Makefile that depends on those. Since
SLUB is the only remaining allocator, remove the allocator choice, make
CONFIG_SLUB a "def_bool y" for now and remove all explicit dependencies
on SLUB or SLAB as it's now always enabled. Make every option's verbose
name and description refer to "the slab allocator" without refering to
the specific implementation. Do not rename the CONFIG_ option names yet.

Everything under #ifdef CONFIG_SLAB, and mm/slab.c is now dead code, all
code under #ifdef CONFIG_SLUB is now always compiled.

Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Christoph Lameter <cl@linux.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 arch/arm64/Kconfig |  2 +-
 arch/s390/Kconfig  |  2 +-
 arch/x86/Kconfig   |  2 +-
 lib/Kconfig.debug  |  1 -
 lib/Kconfig.kasan  | 11 +++------
 lib/Kconfig.kfence |  2 +-
 lib/Kconfig.kmsan  |  2 +-
 mm/Kconfig         | 68 ++++++++++++------------------------------------------
 mm/Kconfig.debug   | 16 ++++---------
 mm/Makefile        |  6 +----
 10 files changed, 28 insertions(+), 84 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 7b071a00425d..325b7140b576 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -154,7 +154,7 @@ config ARM64
 	select HAVE_MOVE_PUD
 	select HAVE_PCI
 	select HAVE_ACPI_APEI if (ACPI && EFI)
-	select HAVE_ALIGNED_STRUCT_PAGE if SLUB
+	select HAVE_ALIGNED_STRUCT_PAGE
 	select HAVE_ARCH_AUDITSYSCALL
 	select HAVE_ARCH_BITREVERSE
 	select HAVE_ARCH_COMPILER_H
diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
index 3bec98d20283..afa42a6f2e09 100644
--- a/arch/s390/Kconfig
+++ b/arch/s390/Kconfig
@@ -146,7 +146,7 @@ config S390
 	select GENERIC_TIME_VSYSCALL
 	select GENERIC_VDSO_TIME_NS
 	select GENERIC_IOREMAP if PCI
-	select HAVE_ALIGNED_STRUCT_PAGE if SLUB
+	select HAVE_ALIGNED_STRUCT_PAGE
 	select HAVE_ARCH_AUDITSYSCALL
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 3762f41bb092..3f460f334d4e 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -169,7 +169,7 @@ config X86
 	select HAS_IOPORT
 	select HAVE_ACPI_APEI			if ACPI
 	select HAVE_ACPI_APEI_NMI		if ACPI
-	select HAVE_ALIGNED_STRUCT_PAGE		if SLUB
+	select HAVE_ALIGNED_STRUCT_PAGE
 	select HAVE_ARCH_AUDITSYSCALL
 	select HAVE_ARCH_HUGE_VMAP		if X86_64 || X86_PAE
 	select HAVE_ARCH_HUGE_VMALLOC		if X86_64
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index cc7d53d9dc01..e1765face106 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -1985,7 +1985,6 @@ config FAULT_INJECTION
 config FAILSLAB
 	bool "Fault-injection capability for kmalloc"
 	depends on FAULT_INJECTION
-	depends on SLAB || SLUB
 	help
 	  Provide fault-injection capability for kmalloc.
 
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index fdca89c05745..97e1fdbb5910 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -37,7 +37,7 @@ menuconfig KASAN
 		     (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)) && \
 		    CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
 		   HAVE_ARCH_KASAN_HW_TAGS
-	depends on (SLUB && SYSFS && !SLUB_TINY) || (SLAB && !DEBUG_SLAB)
+	depends on SYSFS && !SLUB_TINY
 	select STACKDEPOT_ALWAYS_INIT
 	help
 	  Enables KASAN (Kernel Address Sanitizer) - a dynamic memory safety
@@ -78,7 +78,7 @@ config KASAN_GENERIC
 	bool "Generic KASAN"
 	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
 	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
-	select SLUB_DEBUG if SLUB
+	select SLUB_DEBUG
 	select CONSTRUCTORS
 	help
 	  Enables Generic KASAN.
@@ -89,13 +89,11 @@ config KASAN_GENERIC
 	  overhead of ~50% for dynamic allocations.
 	  The performance slowdown is ~x3.
 
-	  (Incompatible with CONFIG_DEBUG_SLAB: the kernel does not boot.)
-
 config KASAN_SW_TAGS
 	bool "Software Tag-Based KASAN"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
 	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
-	select SLUB_DEBUG if SLUB
+	select SLUB_DEBUG
 	select CONSTRUCTORS
 	help
 	  Enables Software Tag-Based KASAN.
@@ -110,12 +108,9 @@ config KASAN_SW_TAGS
 	  May potentially introduce problems related to pointer casting and
 	  comparison, as it embeds a tag into the top byte of each pointer.
 
-	  (Incompatible with CONFIG_DEBUG_SLAB: the kernel does not boot.)
-
 config KASAN_HW_TAGS
 	bool "Hardware Tag-Based KASAN"
 	depends on HAVE_ARCH_KASAN_HW_TAGS
-	depends on SLUB
 	help
 	  Enables Hardware Tag-Based KASAN.
 
diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index 459dda9ef619..6fbbebec683a 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -5,7 +5,7 @@ config HAVE_ARCH_KFENCE
 
 menuconfig KFENCE
 	bool "KFENCE: low-overhead sampling-based memory safety error detector"
-	depends on HAVE_ARCH_KFENCE && (SLAB || SLUB)
+	depends on HAVE_ARCH_KFENCE
 	select STACKTRACE
 	select IRQ_WORK
 	help
diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
index ef2c8f256c57..0541d7b079cc 100644
--- a/lib/Kconfig.kmsan
+++ b/lib/Kconfig.kmsan
@@ -11,7 +11,7 @@ config HAVE_KMSAN_COMPILER
 config KMSAN
 	bool "KMSAN: detector of uninitialized values use"
 	depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
-	depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN
+	depends on DEBUG_KERNEL && !KASAN && !KCSAN
 	depends on !PREEMPT_RT
 	select STACKDEPOT
 	select STACKDEPOT_ALWAYS_INIT
diff --git a/mm/Kconfig b/mm/Kconfig
index 89971a894b60..4636870499bb 100644
--- a/mm/Kconfig
+++ b/mm/Kconfig
@@ -226,52 +226,17 @@ config ZSMALLOC_CHAIN_SIZE
 
 	  For more information, see zsmalloc documentation.
 
-menu "SLAB allocator options"
-
-choice
-	prompt "Choose SLAB allocator"
-	default SLUB
-	help
-	   This option allows to select a slab allocator.
-
-config SLAB_DEPRECATED
-	bool "SLAB (DEPRECATED)"
-	depends on !PREEMPT_RT
-	help
-	  Deprecated and scheduled for removal in a few cycles. Replaced by
-	  SLUB.
-
-	  If you cannot migrate to SLUB, please contact linux-mm@kvack.org
-	  and the people listed in the SLAB ALLOCATOR section of MAINTAINERS
-	  file, explaining why.
-
-	  The regular slab allocator that is established and known to work
-	  well in all environments. It organizes cache hot objects in
-	  per cpu and per node queues.
+menu "Slab allocator options"
 
 config SLUB
-	bool "SLUB (Unqueued Allocator)"
-	help
-	   SLUB is a slab allocator that minimizes cache line usage
-	   instead of managing queues of cached objects (SLAB approach).
-	   Per cpu caching is realized using slabs of objects instead
-	   of queues of objects. SLUB can use memory efficiently
-	   and has enhanced diagnostics. SLUB is the default choice for
-	   a slab allocator.
-
-endchoice
-
-config SLAB
-	bool
-	default y
-	depends on SLAB_DEPRECATED
+	def_bool y
 
 config SLUB_TINY
-	bool "Configure SLUB for minimal memory footprint"
-	depends on SLUB && EXPERT
+	bool "Configure for minimal memory footprint"
+	depends on EXPERT
 	select SLAB_MERGE_DEFAULT
 	help
-	   Configures the SLUB allocator in a way to achieve minimal memory
+	   Configures the slab allocator in a way to achieve minimal memory
 	   footprint, sacrificing scalability, debugging and other features.
 	   This is intended only for the smallest system that had used the
 	   SLOB allocator and is not recommended for systems with more than
@@ -282,7 +247,6 @@ config SLUB_TINY
 config SLAB_MERGE_DEFAULT
 	bool "Allow slab caches to be merged"
 	default y
-	depends on SLAB || SLUB
 	help
 	  For reduced kernel memory fragmentation, slab caches can be
 	  merged when they share the same size and other characteristics.
@@ -296,7 +260,7 @@ config SLAB_MERGE_DEFAULT
 
 config SLAB_FREELIST_RANDOM
 	bool "Randomize slab freelist"
-	depends on SLAB || (SLUB && !SLUB_TINY)
+	depends on !SLUB_TINY
 	help
 	  Randomizes the freelist order used on creating new pages. This
 	  security feature reduces the predictability of the kernel slab
@@ -304,21 +268,19 @@ config SLAB_FREELIST_RANDOM
 
 config SLAB_FREELIST_HARDENED
 	bool "Harden slab freelist metadata"
-	depends on SLAB || (SLUB && !SLUB_TINY)
+	depends on !SLUB_TINY
 	help
 	  Many kernel heap attacks try to target slab cache metadata and
 	  other infrastructure. This options makes minor performance
 	  sacrifices to harden the kernel slab allocator against common
-	  freelist exploit methods. Some slab implementations have more
-	  sanity-checking than others. This option is most effective with
-	  CONFIG_SLUB.
+	  freelist exploit methods.
 
 config SLUB_STATS
 	default n
-	bool "Enable SLUB performance statistics"
-	depends on SLUB && SYSFS && !SLUB_TINY
+	bool "Enable performance statistics"
+	depends on SYSFS && !SLUB_TINY
 	help
-	  SLUB statistics are useful to debug SLUBs allocation behavior in
+	  The statistics are useful to debug slab allocation behavior in
 	  order find ways to optimize the allocator. This should never be
 	  enabled for production use since keeping statistics slows down
 	  the allocator by a few percentage points. The slabinfo command
@@ -328,8 +290,8 @@ config SLUB_STATS
 
 config SLUB_CPU_PARTIAL
 	default y
-	depends on SLUB && SMP && !SLUB_TINY
-	bool "SLUB per cpu partial cache"
+	depends on SMP && !SLUB_TINY
+	bool "Enable per cpu partial caches"
 	help
 	  Per cpu partial caches accelerate objects allocation and freeing
 	  that is local to a processor at the price of more indeterminism
@@ -339,7 +301,7 @@ config SLUB_CPU_PARTIAL
 
 config RANDOM_KMALLOC_CACHES
 	default n
-	depends on SLUB && !SLUB_TINY
+	depends on !SLUB_TINY
 	bool "Randomize slab caches for normal kmalloc"
 	help
 	  A hardening feature that creates multiple copies of slab caches for
@@ -354,7 +316,7 @@ config RANDOM_KMALLOC_CACHES
 	  limited degree of memory and CPU overhead that relates to hardware and
 	  system workload.
 
-endmenu # SLAB allocator options
+endmenu # Slab allocator options
 
 config SHUFFLE_PAGE_ALLOCATOR
 	bool "Page allocator randomization"
diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index 018a5bd2f576..321ab379994f 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -45,18 +45,10 @@ config DEBUG_PAGEALLOC_ENABLE_DEFAULT
 	  Enable debug page memory allocations by default? This value
 	  can be overridden by debug_pagealloc=off|on.
 
-config DEBUG_SLAB
-	bool "Debug slab memory allocations"
-	depends on DEBUG_KERNEL && SLAB
-	help
-	  Say Y here to have the kernel do limited verification on memory
-	  allocation as well as poisoning memory on free to catch use of freed
-	  memory. This can make kmalloc/kfree-intensive workloads much slower.
-
 config SLUB_DEBUG
 	default y
 	bool "Enable SLUB debugging support" if EXPERT
-	depends on SLUB && SYSFS && !SLUB_TINY
+	depends on SYSFS && !SLUB_TINY
 	select STACKDEPOT if STACKTRACE_SUPPORT
 	help
 	  SLUB has extensive debug support features. Disabling these can
@@ -66,7 +58,7 @@ config SLUB_DEBUG
 
 config SLUB_DEBUG_ON
 	bool "SLUB debugging on by default"
-	depends on SLUB && SLUB_DEBUG
+	depends on SLUB_DEBUG
 	select STACKDEPOT_ALWAYS_INIT if STACKTRACE_SUPPORT
 	default n
 	help
@@ -231,8 +223,8 @@ config DEBUG_KMEMLEAK
 	  allocations. See Documentation/dev-tools/kmemleak.rst for more
 	  details.
 
-	  Enabling DEBUG_SLAB or SLUB_DEBUG may increase the chances
-	  of finding leaks due to the slab objects poisoning.
+	  Enabling SLUB_DEBUG may increase the chances of finding leaks
+	  due to the slab objects poisoning.
 
 	  In order to access the kmemleak file, debugfs needs to be
 	  mounted (usually at /sys/kernel/debug).
diff --git a/mm/Makefile b/mm/Makefile
index 33873c8aedb3..e4b5b75aaec9 100644
--- a/mm/Makefile
+++ b/mm/Makefile
@@ -4,7 +4,6 @@
 #
 
 KASAN_SANITIZE_slab_common.o := n
-KASAN_SANITIZE_slab.o := n
 KASAN_SANITIZE_slub.o := n
 KCSAN_SANITIZE_kmemleak.o := n
 
@@ -12,7 +11,6 @@ KCSAN_SANITIZE_kmemleak.o := n
 # the same word but accesses to different bits of that word. Re-enable KCSAN
 # for these when we have more consensus on what to do about them.
 KCSAN_SANITIZE_slab_common.o := n
-KCSAN_SANITIZE_slab.o := n
 KCSAN_SANITIZE_slub.o := n
 KCSAN_SANITIZE_page_alloc.o := n
 # But enable explicit instrumentation for memory barriers.
@@ -22,7 +20,6 @@ KCSAN_INSTRUMENT_BARRIERS := y
 # flaky coverage that is not a function of syscall inputs. E.g. slab is out of
 # free pages, or a task is migrated between nodes.
 KCOV_INSTRUMENT_slab_common.o := n
-KCOV_INSTRUMENT_slab.o := n
 KCOV_INSTRUMENT_slub.o := n
 KCOV_INSTRUMENT_page_alloc.o := n
 KCOV_INSTRUMENT_debug-pagealloc.o := n
@@ -66,6 +63,7 @@ obj-y += page-alloc.o
 obj-y += init-mm.o
 obj-y += memblock.o
 obj-y += $(memory-hotplug-y)
+obj-y += slub.o
 
 ifdef CONFIG_MMU
 	obj-$(CONFIG_ADVISE_SYSCALLS)	+= madvise.o
@@ -82,8 +80,6 @@ obj-$(CONFIG_SPARSEMEM_VMEMMAP) += sparse-vmemmap.o
 obj-$(CONFIG_MMU_NOTIFIER) += mmu_notifier.o
 obj-$(CONFIG_KSM) += ksm.o
 obj-$(CONFIG_PAGE_POISONING) += page_poison.o
-obj-$(CONFIG_SLAB) += slab.o
-obj-$(CONFIG_SLUB) += slub.o
 obj-$(CONFIG_KASAN)	+= kasan/
 obj-$(CONFIG_KFENCE) += kfence/
 obj-$(CONFIG_KMSAN)	+= kmsan/

-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-2-9c9c70177183%40suse.cz.
