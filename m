Return-Path: <kasan-dev+bncBCH67JWTV4DBBCXVRDYQKGQE2XMHFIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F95A141458
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 23:51:55 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id a21sf257840lfg.4
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 14:51:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579301514; cv=pass;
        d=google.com; s=arc-20160816;
        b=gCXYHTgnWzo4I1i9YGZN7PnG8jqsQVPFGRlTObBg6YWKZakLiDf8l7mvCkL8BR3Zqn
         rafv3MaGV1dwNT3/1QFqHcd/k+QlNgdq6h/JM7cMrOz7twST/zO7/Iraqm6bVzIGonXL
         W1yHXzrw/bMVkSGctr+4+ui2Ttjjnmgp10nx8YsuWW4GyMEFLmlQvu4UBJz+sdo4pNn0
         3HjLiZovUCT2gMCuWZ11ilCCx393WLdXpPFbt+Ll6V8ytGEHiXn0LESEjOHrAkgoNiqI
         ureMiIDU4anLgIlGv7tJwHcFaTJuby784srvxpCAOFmvfgO6PEqbrBNdSpNlMuVLFfv3
         Swow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=WJRZKLHegNreiTo4Gk7aGNVSbgc9OIGeBi+CcYpXNVQ=;
        b=rKyXp0VJXAwFR2V8gRdyzcbC4rWFQ7i0QpsHFPgMERQlhSduMdI6htfpqr+SQmVw82
         c/6S/rNFekPjXSHR2A+2Nf4qiG8zWxbwqepQ9ZaDmA6Rht8Ete5/o8Pfh9WDCEA8QQa0
         IRroIhDWrs86vNwfnlx4o4/G079ECfJXLgblD3EWIzkW4hDMD2/Hp0AbcqFVbRWsdIGM
         ab3ypBlPM8Y3tX9i2499LtfcXA7uW77GJlsa6SO95xH9mY94YPm+84QXkWw1NU9Ox7PA
         ennK5Cdpn6E3j95pPVkbMPAiPaH4B95Kb9z6uCjwjYnDLs+QwMG/TzZWCH1sgGDDWWax
         v/BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Cb3k7qTY;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WJRZKLHegNreiTo4Gk7aGNVSbgc9OIGeBi+CcYpXNVQ=;
        b=hfftof/SBoD2WUOpOQ6jQTHZQT+sqUOxptDtiN2FWMZQyCCuXc9LxShDuItOnANs0B
         3J2FKVhMcA6A6ihCtCtmRbl57qSexISR27fpKHx4ZN2Pyt7dXiJlAOe8t81Eertf58cw
         Qx/g3+U1qy71TXoomwGALln1bFIb/diMJDYMHI9H3jPzEUj7Z4rO04tjoaUC53c5lfls
         q2C75Am3rQwaxCT6V1Wq6ViCTHXnEVunqMnb7OzIpDkg7YXqxLYSKl9Gz9Z+kWPAKagU
         o4uFTI0ns3IvxwtP9b6NvcPIRQJF5xssCQDoNtjATwDn88oO8QKy9w93jlwZIPTNEVIK
         0Umw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WJRZKLHegNreiTo4Gk7aGNVSbgc9OIGeBi+CcYpXNVQ=;
        b=cRqgCqnWaE23FKMEeohlltYCzvfI2uNYvWoFKuou05k2SFe69oLJ19pAmW+ybkUP7g
         NpEZn5Tj0zXCGAQ9rlz0K3JaP3SlCOyAJron+H6cfWVZQ9MfKyovRUySeq4V1at6Qcq4
         ppyeq+LrWH4VrXEagY1VPdkunNDvMrJy98oKGdpJtcEeWzZi9Q6IBNVGO5gYcCGL6UXN
         JjNmMKLfkkOcDIRloZDp6XOKqfmsAxJvRv5iCty3ig8ZSx5ykUGdZFtJlPtw0yNCDxsI
         5l75nTZnQsEfb5mfa/BGQhNivWPFwVS67XMrCPBJsYBw1SGOtx+SefWD6gXX+9FJeO6y
         MK5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WJRZKLHegNreiTo4Gk7aGNVSbgc9OIGeBi+CcYpXNVQ=;
        b=jLgJ66QeZ3q3iZFyl6w/i4lYjyTa9tecojfxM/RYiMYUeriv5r9Ghx11zvyl2k1wjD
         fnxMIJe/8V+MYEYNfmSwnDj+qw7ooqG4/5pgVva+7BEhFvZJ4Mp/66ULHfb6p3ddhcHD
         ExfRoed8xAP3J9hRbKKPv1dEyaeHlxI3qkbAq/bPqoPcEzZ7V+BcSE3FKU97daj2bV1Y
         +QgHacjV6YWqkSKRnmbhEu9bmaF6hM/vW3CbTN6tGDGnLDL0mpA+xLSEMffFdUKWwIo7
         7Xw4VACF/Fw5qQX2ZbXtQYE/aNqH4QsdkrF+0vXrHhR7oVi2ZjLzMtGHQnW24pkiRMW0
         t4UQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXVI6plf5V1ZEI0J9zh6Ya5SvSFokJz83slp/zH3BpI2pZNQBfC
	EtW7CnLT9V9jAOTX1iaI5PE=
X-Google-Smtp-Source: APXvYqy8i/oOY/snO3C4HfklqeZt9J4ACL3UxNx7bLl+XkxZ1BGlfpdvkefo5ebcs+UklIYm9qYd7w==
X-Received: by 2002:a2e:8512:: with SMTP id j18mr7030098lji.269.1579301514643;
        Fri, 17 Jan 2020 14:51:54 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:988d:: with SMTP id b13ls3729134ljj.6.gmail; Fri, 17 Jan
 2020 14:51:53 -0800 (PST)
X-Received: by 2002:a2e:974b:: with SMTP id f11mr7023469ljj.173.1579301513902;
        Fri, 17 Jan 2020 14:51:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579301513; cv=none;
        d=google.com; s=arc-20160816;
        b=sKRHxEZ63OdtMp4vJRiwx0z0rMEhJnKvlKTLP8j/DZdoB7qzthoIAvuaKQCy8SVg/8
         0Rl88q3xIiFPLTkl6mCgcjThwBpKRyY4/s0qIkk6CNYYVP4jHxwd4PqPgiZ2ekUjREXB
         yCknSW8jd2GYYJxb4oBdw5+BOHplFZFNLzZHe0D30EHjhybllRZvAU3rD7vMB0yRjtMv
         xa8YgMd1wbvzqj3uPfNZY1c0MTSqK3sfbZIj4e8GPmUz9BfSzl5Pl1WcUtabNgzPiBWz
         QRMI2yNrgTLnNbTjwN0xuUVO26f9FHmzXx2S/9S/40OLrv+jaeTnTccfPboTR/PhZZ/A
         nUQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=x0se5PsWKgfvt31l3mqEKGiEnfoaKNuR8Ii/GhrHCb0=;
        b=vVoHNvzPKvkBBnC4UTIBazPC+/TJoVN+WUkn48CmoPZlFsQalFGVgaWG8vTODNBHnR
         mQm8q6qnjUi44nS9TbQ30DuhN7gbD/pA+NmkVfvE9dZLcssuqukwGrEYeNsXz2hDkN5Z
         0Jj+VtDQNvoc4NWjQRMsjtAF8sbcGWUSmtnTZR7rOQeizbR9xoWoQ6gHNzTW7QjtAZi2
         bZp+uk/vj880wr4vo3s2CMZbri9eVmZ6yojBvvWX9pnGa7z73lW61PJLe+1KgaxplaCk
         XDyeeZJWvJ2PWA4nr1ClPmmsDQpDHriWmX1VgjXXUrIttHxjhnEltzepLYmfyGIVvL4d
         257g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Cb3k7qTY;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id a4si625855lfg.1.2020.01.17.14.51.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 14:51:53 -0800 (PST)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id w5so10424217wmi.1
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 14:51:53 -0800 (PST)
X-Received: by 2002:a7b:c5d8:: with SMTP id n24mr6796728wmk.124.1579301513296;
        Fri, 17 Jan 2020 14:51:53 -0800 (PST)
Received: from fainelli-desktop.igp.broadcom.net ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id l3sm32829387wrt.29.2020.01.17.14.51.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 Jan 2020 14:51:52 -0800 (PST)
From: Florian Fainelli <f.fainelli@gmail.com>
To: linux-arm-kernel@lists.infradead.org
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Abbott Liu <liuwenliang@huawei.com>,
	Florian Fainelli <f.fainelli@gmail.com>,
	bcm-kernel-feedback-list@broadcom.com,
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
Subject: [PATCH v7 3/7] ARM: Disable instrumentation for some code
Date: Fri, 17 Jan 2020 14:48:35 -0800
Message-Id: <20200117224839.23531-4-f.fainelli@gmail.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200117224839.23531-1-f.fainelli@gmail.com>
References: <20200117224839.23531-1-f.fainelli@gmail.com>
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Cb3k7qTY;       spf=pass
 (google.com: domain of f.fainelli@gmail.com designates 2a00:1450:4864:20::344
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
arch/arm/vdso/* because that code would not linkd with kernel image.

Disable instrumentation for arch/arm/kvm/hyp/*. See commit a6cdf1c08cbf
("kvm: arm64: Disable compiler instrumentation for hypervisor code") for
more details.

Disable instrumentation for arch/arm/mm/physaddr.c. See commit
ec6d06efb0ba ("arm64: Add support for CONFIG_DEBUG_VIRTUAL") for more
details.

Disable kasan check in the function unwind_pop_register because it does
not matter that kasan checks failed when unwind_pop_register read stack
memory of task.

Reported-by: Florian Fainelli <f.fainelli@gmail.com>
Reported-by: Marc Zyngier <marc.zyngier@arm.com>
Tested-by: Linus Walleij <linus.walleij@linaro.org>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
---
 arch/arm/boot/compressed/Makefile | 1 +
 arch/arm/kernel/unwind.c          | 6 +++++-
 arch/arm/mm/Makefile              | 1 +
 arch/arm/vdso/Makefile            | 2 ++
 4 files changed, 9 insertions(+), 1 deletion(-)

diff --git a/arch/arm/boot/compressed/Makefile b/arch/arm/boot/compressed/Makefile
index a1e883c5e5c4..83991a0447fa 100644
--- a/arch/arm/boot/compressed/Makefile
+++ b/arch/arm/boot/compressed/Makefile
@@ -24,6 +24,7 @@ OBJS		+= hyp-stub.o
 endif
 
 GCOV_PROFILE		:= n
+KASAN_SANITIZE		:= n
 
 # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
 KCOV_INSTRUMENT		:= n
diff --git a/arch/arm/kernel/unwind.c b/arch/arm/kernel/unwind.c
index 4574e6aea0a5..f73601416f90 100644
--- a/arch/arm/kernel/unwind.c
+++ b/arch/arm/kernel/unwind.c
@@ -236,7 +236,11 @@ static int unwind_pop_register(struct unwind_ctrl_block *ctrl,
 		if (*vsp >= (unsigned long *)ctrl->sp_high)
 			return -URC_FAILURE;
 
-	ctrl->vrs[reg] = *(*vsp)++;
+	/* Use READ_ONCE_NOCHECK here to avoid this memory access
+	 * from being tracked by KASAN.
+	 */
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
index 0fda344beb0b..1f76a5ff6e49 100644
--- a/arch/arm/vdso/Makefile
+++ b/arch/arm/vdso/Makefile
@@ -42,6 +42,8 @@ GCOV_PROFILE := n
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200117224839.23531-4-f.fainelli%40gmail.com.
