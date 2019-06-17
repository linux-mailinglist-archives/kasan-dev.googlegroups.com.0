Return-Path: <kasan-dev+bncBCH67JWTV4DBBIVAUDUAKGQE7LAX2RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id CB371494D3
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 00:11:47 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id f11sf3183644otq.3
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 15:11:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560809506; cv=pass;
        d=google.com; s=arc-20160816;
        b=r75Qc5UBqo8Lsv4/jHmKxxem8/ygUj2FJU2dX7v6uynQ2slqtmC0xxRzTmQEXkDPiT
         +dxiwpTF1paJk9CKlWwqfeaWMr7iQv3X4J6kd1X2ztkdkXPngjxXG/gq5w3QQqq9KyNg
         n0hKq4AbP18FB9Rk4FJMpZF2p8XtmVdt9zqp9lENZ7vsF88cZ1ufEL41hlueULYvfFyM
         X7TGyM086/NcvHNcxapDjgdwtXC7pjNXznkIO7ElcagaHO81dBFvuIaOJ3wmEnF/cbfT
         WOrN0iR6G9m7K0VYyv/ErSoD2qeTFPAwOzRDLxgIqV6xdpdVcZUvpU+n819c9b4EhauI
         9TGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=5jkjA6mUCinSkov9WZqCDsfw1l9Jnq+M1Y03x1zKH64=;
        b=JJ4I+bmqbVIToaK/VdI/HzMpLroCyo+2oXRbymhWKj8lur4to4BGSLu/s9hYhwsTcf
         eMpep+SnogWbdmz1wYEZznt7JPI1AupnFKGGWdq8xcaS/Ae3HZXGt/a0ST8gkrWIVQNp
         iFiEmuamLZ9zPQlJYzw2oQy9/Ir+iRb9jZfnFJrOba4EtYJW+Vjmqk4kLhKFKnEaNB99
         4R73WUgql/reK2XTc/aMTfg6H3sEQuWNSWiFmJ46qvMPx46NAosh5V9zqMT9SvRP9stx
         9qLMhkf3KYrEXXnKUhW6YnT4gaW0GoLN8tDOldIqg1Idn8tRoAylvMwr4dmSRU2wzsTt
         mIeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ktB3GFf5;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5jkjA6mUCinSkov9WZqCDsfw1l9Jnq+M1Y03x1zKH64=;
        b=QL38D0tvnqQ3fBxvlNPm7JW/G2m8pYjRsrIg0S0hReF4RSd1RCIYxRzxirpDwXyuZG
         88M6TQ4WbaFyFxxZA5B1LJgIbVYAmyjzmaSBuOqWqTCrT3OjuMPYr7fxwsx3rfzMvIGI
         P7JTlT60PRuj0GysDBxY3+zEvxQ/jGRklIocxfZaVWic5Wge/RhlKJEEbvYnskoFDzaX
         cSxlslmS6gj+DSU/Ml4bupGCG0Jv5JjCRF7qaI7kzWRnMWmaAEEeKuwex46s/Gk5R6kw
         TLya63Wzt+pVpftQPdNAxmaQwxqlDeevyUYchrgxa0+4SihiUXZ6bRcUEVl4S5VbybSf
         ZNYA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5jkjA6mUCinSkov9WZqCDsfw1l9Jnq+M1Y03x1zKH64=;
        b=MYoKWIEE7rCl9XZhRBNu5ueGucNRuYPvJLmrNga269Xe2vbYOkn0JQTD4M9hJRxsgO
         vhFKfNkHNQZMFiMgEy9lZpMiAb9TLLh/hLhDfFG/Gxxyh9iyQV3CR07nalPJir5TRE8z
         2pAEXsv9i+llcjhbaIPRCSJJUPAU5yCXUD6+1qfvk27N/uZHmRL0eqsc4meQOa71cOWt
         /UysrTLIOMthzBMnnPUFiOhUM+J/8SgsiD8Fot5V50TD0z2D7n5aLtQy+BkP1hIrDcl8
         0vyAJ342jHHdar8goqiFk/weXPyyHQ+PLYL5tPJiB198TE8/cLHwKCGf0WboI6Yw3njP
         ukOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5jkjA6mUCinSkov9WZqCDsfw1l9Jnq+M1Y03x1zKH64=;
        b=gwnkDJVPbXTzeqZPj8w3oXZ0K+TI9kuiL2L7GnB7vwNmtQHSQPT/KpRjtpNWrMNYia
         fTZgVJuiHfRLxOazmTZmAWujwImtRbADFfIbn8JPSaz9rEIUGC+GKmfwa76VIT7m6bxY
         4KUD3PARu6qoAEkUxrFJqc56vSfI2k//sDpieO8GsSUx9jSBTT7I3xJaYOuVH0JiE/NJ
         eiA5oiLQ+4we0LitHp8u1YFWDk7zW+Z/Myr/VskHzFXSkgWp0wVI0a+jza2y13qhnrLZ
         DIXNUrmzNiEJZvhap3qUMrUgfGl76nh5uIjpaYsUSSCIORG3t7f4sWlfvu1sV4Za+T3a
         ybPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUfIh0FHPCPnlI4SSm623ISf9R8kFb8TXdikc9jgYdpdATMTBwt
	V+oD1X9w67fbi+XwX+tyREM=
X-Google-Smtp-Source: APXvYqzRbFDjN2rrlfLJuAXeH3/45bEw9rBrkkQ8SRoD/388vB5NosWR/ZbT5zoNs5PQc9x0F61/Cw==
X-Received: by 2002:a05:6830:15cd:: with SMTP id j13mr1521558otr.110.1560809506708;
        Mon, 17 Jun 2019 15:11:46 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:560a:: with SMTP id e10ls3416898oti.1.gmail; Mon, 17 Jun
 2019 15:11:46 -0700 (PDT)
X-Received: by 2002:a9d:3d64:: with SMTP id a91mr62876457otc.258.1560809506310;
        Mon, 17 Jun 2019 15:11:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560809506; cv=none;
        d=google.com; s=arc-20160816;
        b=CAv0w6hqDRleEqwesGuzvs1FFYGE/pP7rrXlyeZwShVBt5wZG58BPlefMBXadfldYt
         T3PsWmqaF2+uxqwbseYECarTTz+6intch2tjT4o9KYM7QdpRipSBk4anLWEszJVcWZf3
         8cQrh2rCBoEoL4yhlLX2h+jHrsHG/bwfQ8ktTm3aBc2HnoK0omRe/3oNhQGy3I0siXF0
         phuEGd/oQKUaCZfPEnDyDfqc5vQkcLafcvidNaBsZ83P0n+dsC3ohu7UvK1yxYHr04CG
         3G28SBcUpZux5BYy61PnEz8bKWg1VrnbXPqKrNmg14QLU4qHAJ4zHkLsqLgKlw7kI+BE
         zJKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=dXXVrwVJ7l6qanDf/467EF9XBDIFBZuBR9eikjI7P94=;
        b=zY8OR4LnkkZ3FFAMZ24rmq0cbVl9eSjU/SmlJlmurHWATQuSLlp/KzDfQjiFvsEBHE
         a6l7wBh2qvkxDF/B1k0wRQSoTveA0bQ3V5bYNGnettmhUJozlvqL6T78/77nxxBl8qqf
         6E6eSLUPtZ4raYNkWlq8ImPt2WC4WHd34sEYPBbgz+gfaxNVaozds+liTW820JO4/TUj
         kcr57LGG6oZ1mfMW/d30mVk0zzl6xu2RDacOxRve4gmOJ+JgSoO2x8odhm031jO2VSWO
         MEK6OSALt/Evc8KKbEiU0UIAaA/aos9qSBiaqpc6Fmq5R/q3kSAE0c5+GSd2kudbUVYN
         c4mQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ktB3GFf5;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id a142si763913oii.5.2019.06.17.15.11.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 15:11:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id cl9so4739613plb.10
        for <kasan-dev@googlegroups.com>; Mon, 17 Jun 2019 15:11:46 -0700 (PDT)
X-Received: by 2002:a17:902:a5ca:: with SMTP id t10mr102286611plq.98.1560809505570;
        Mon, 17 Jun 2019 15:11:45 -0700 (PDT)
Received: from fainelli-desktop.igp.broadcom.net ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id s129sm12551020pfb.186.2019.06.17.15.11.43
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Mon, 17 Jun 2019 15:11:44 -0700 (PDT)
From: Florian Fainelli <f.fainelli@gmail.com>
To: linux-arm-kernel@lists.infradead.org
Cc: bcm-kernel-feedback-list@broadcom.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Florian Fainelli <f.fainelli@gmail.com>,
	glider@google.com,
	dvyukov@google.com,
	corbet@lwn.net,
	linux@armlinux.org.uk,
	christoffer.dall@arm.com,
	marc.zyngier@arm.com,
	arnd@arndb.de,
	nico@fluxnic.net,
	vladimir.murzin@arm.com,
	keescook@chromium.org,
	jinb.park7@gmail.com,
	alexandre.belloni@bootlin.com,
	ard.biesheuvel@linaro.org,
	daniel.lezcano@linaro.org,
	pombredanne@nexb.com,
	rob@landley.net,
	gregkh@linuxfoundation.org,
	akpm@linux-foundation.org,
	mark.rutland@arm.com,
	catalin.marinas@arm.com,
	yamada.masahiro@socionext.com,
	tglx@linutronix.de,
	thgarnie@google.com,
	dhowells@redhat.com,
	geert@linux-m68k.org,
	andre.przywara@arm.com,
	julien.thierry@arm.com,
	drjones@redhat.com,
	philip@cog.systems,
	mhocko@suse.com,
	kirill.shutemov@linux.intel.com,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kvmarm@lists.cs.columbia.edu,
	ryabinin.a.a@gmail.com
Subject: [PATCH v6 2/6] ARM: Disable instrumentation for some code
Date: Mon, 17 Jun 2019 15:11:30 -0700
Message-Id: <20190617221134.9930-3-f.fainelli@gmail.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20190617221134.9930-1-f.fainelli@gmail.com>
References: <20190617221134.9930-1-f.fainelli@gmail.com>
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=ktB3GFf5;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::643
 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

From: Andrey Ryabinin <aryabinin@virtuozzo.com>

Disable instrumentation for arch/arm/boot/compressed/* and
arch/arm/vdso/* because those code won't linkd with kernel image.

Disable instrumentation for arch/arm/kvm/hyp/*. See commit a6cdf1c08cbf
("kvm: arm64: Disable compiler instrumentation for hypervisor code") for
more details.

Disable instrumentation for arch/arm/mm/physaddr.c. See commit
ec6d06efb0ba ("arm64: Add support for CONFIG_DEBUG_VIRTUAL") for more
details.

Disable kasan check in the function unwind_pop_register because it
doesn't matter that kasan checks failed when unwind_pop_register read
stack memory of task.

Reported-by: Florian Fainelli <f.fainelli@gmail.com>
Reported-by: Marc Zyngier <marc.zyngier@arm.com>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
---
 arch/arm/boot/compressed/Makefile | 1 +
 arch/arm/kernel/unwind.c          | 3 ++-
 arch/arm/mm/Makefile              | 1 +
 arch/arm/vdso/Makefile            | 2 ++
 4 files changed, 6 insertions(+), 1 deletion(-)

diff --git a/arch/arm/boot/compressed/Makefile b/arch/arm/boot/compressed/Makefile
index 9219389bbe61..fa4d1fddf1db 100644
--- a/arch/arm/boot/compressed/Makefile
+++ b/arch/arm/boot/compressed/Makefile
@@ -24,6 +24,7 @@ OBJS		+= hyp-stub.o
 endif
 
 GCOV_PROFILE		:= n
+KASAN_SANITIZE		:= n
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
 KCOV_INSTRUMENT		:= n
diff --git a/arch/arm/kernel/unwind.c b/arch/arm/kernel/unwind.c
index 4574e6aea0a5..b70fb260c28a 100644
--- a/arch/arm/kernel/unwind.c
+++ b/arch/arm/kernel/unwind.c
@@ -236,7 +236,8 @@ static int unwind_pop_register(struct unwind_ctrl_block *ctrl,
 		if (*vsp >= (unsigned long *)ctrl->sp_high)
 			return -URC_FAILURE;
 
-	ctrl->vrs[reg] = *(*vsp)++;
+	ctrl->vrs[reg] = READ_ONCE_NOCHECK(*(*vsp));
+	(*vsp)++;
 	return URC_OK;
 }
 
diff --git a/arch/arm/mm/Makefile b/arch/arm/mm/Makefile
index 7cb1699fbfc4..432302911d6e 100644
--- a/arch/arm/mm/Makefile
+++ b/arch/arm/mm/Makefile
@@ -16,6 +16,7 @@ endif
 obj-$(CONFIG_ARM_PTDUMP_CORE)	+= dump.o
 obj-$(CONFIG_ARM_PTDUMP_DEBUGFS)	+= ptdump_debugfs.o
 obj-$(CONFIG_MODULES)		+= proc-syms.o
+KASAN_SANITIZE_physaddr.o	:= n
 obj-$(CONFIG_DEBUG_VIRTUAL)	+= physaddr.o
 
 obj-$(CONFIG_ALIGNMENT_TRAP)	+= alignment.o
diff --git a/arch/arm/vdso/Makefile b/arch/arm/vdso/Makefile
index fadf554d9391..855fa82bf3ec 100644
--- a/arch/arm/vdso/Makefile
+++ b/arch/arm/vdso/Makefile
@@ -33,6 +33,8 @@ GCOV_PROFILE := n
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
 KCOV_INSTRUMENT := n
 
+KASAN_SANITIZE := n
+
 # Force dependency
 $(obj)/vdso.o : $(obj)/vdso.so
 
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190617221134.9930-3-f.fainelli%40gmail.com.
For more options, visit https://groups.google.com/d/optout.
