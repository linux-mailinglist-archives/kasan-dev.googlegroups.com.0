Return-Path: <kasan-dev+bncBCH67JWTV4DBBLFAUDUAKGQERSUI44A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id B5C6A494D9
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2019 00:11:57 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id t196sf10492492qke.0
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2019 15:11:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560809516; cv=pass;
        d=google.com; s=arc-20160816;
        b=wxj40zArAdJroMr7qyZUJrxSCmP/UxZkHxXKFKmIZG9qkyI0lz/xu+afLqB6Ms1rI8
         BS+MZJ78Tojhs8Pw5rzfpzuFr7bvD6x3RXGpWHwMSI+gQJ0GxDl9V22V3UKcPahTFzz4
         5Eb6wnb5lXlZf/pco7rH66SKxN8lLGMYNZ8UCozFZ7BCP7nvvOMEqX98JT7hvWk5+iIh
         c9YRAHu7fjFf3+eLEG85UI5MTF4YV67ScxGP96qeX4l7yojCYMSCWZz2JxXN7laz7Vdd
         LVTkuX+u1AGM4YXkJr5ECMdBhTAKnfxJ1WRfsGCaUyS9ijMU3MswfNncQM1hJs38f99l
         1aiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=gP9TSCpvxHomMGEHNsfw2c+FA6yYbKYFvTHvA4DFjNs=;
        b=ZCFgmEQM7nBQLyW0KDk++JR9Zsrkz2v+ixFz5IzwcvBR2ftNr6WrjbXsCZN2mCk8GN
         AUv/nC//4OOoqrL9EBnh6JuLI6UMmiW+l8wsJoKJGEPpW32nnN6/mDvmntr2KYbqWq2N
         YaCSWXwoDBKgKvnfKreDxpxliDUIZXPPixD3fNXurx/mTNuARxOWjkxY2uklxg/EMfMg
         mRgffO6Cm1bvFgKG8DxUj2KqzWzUJJMyx9famOHgBhUI/uW9vqkAL+Dh5ZpboiX5+WEk
         uT4/PIYfF8zvL2UW5a6YEdd1p9MOzsgt3QwapuSYSgLbf5y8EnyqKALuDgPe0TMGpHMw
         7caw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=HsMQvlLI;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gP9TSCpvxHomMGEHNsfw2c+FA6yYbKYFvTHvA4DFjNs=;
        b=jG/dcSowNP6+7F83SioQ+UozgLCAbv07PBGK2J446dJC5cONAGxmQVWNi1LqipfbCJ
         hQ8jFcN6ohgzMcuszl2fipRGW3EKUOm+PFdzpNklkSUeCEYWxCRPCCpmaQ5BZgNDup3s
         zXImaC8fHIPj7AWU2oitQA+FefwHserTlmLzThfe7OjXuzeL3Md5455Gb/+lKHIPDbDh
         OirTagQEjb5Au2Wf0N0YbzUsTQP7zCtlg0NGl6RWJRESgbwvlUrCgS7MSI7x81RR4qpG
         hF8OZNu3jbSsxXe+Ny6gx4pXa+GNnXSlDvQ3gZ2a3UKwhLB4xVRl5/LX3Z2qfG5zix/Q
         Zd+A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gP9TSCpvxHomMGEHNsfw2c+FA6yYbKYFvTHvA4DFjNs=;
        b=Xo+E1++ktINCPVPIQGekqADjZhQplTc7NaTTK51h7Bx7PSx5q+WA6fejKapyipKXFE
         em/IajlIkRifkm35n2sOlr11WzJdadlw7nhuiGNx9iooT4NZ/3N+EUSErHiLSgx17r+P
         6AIFjP8RhAbprY51++C1zXi1iKnS7O0rFmjyQLo6dL2UjFUajWVp7bH5D9jSaz8b6S0q
         8O0QooTdJfJI7ZxNHp+u8wLDB09IsnWR0FGii+96O8du7O/nOtUpNkYMDLPUrMxkOj1l
         jutskTmFvv8PccCiMiBAJo4SUo5nL+nYf8qXv63cvsB3OaPpSa4ir853yPwoKEb75jPW
         VlCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gP9TSCpvxHomMGEHNsfw2c+FA6yYbKYFvTHvA4DFjNs=;
        b=gejuhtwIbXh/XKkdm/Z4J+fAoj8Eo3xTPnthFGcHVLA0Deo2FSH2/x1GJqykLY72rQ
         9vJ+c6oKGYhqFQUILqUYYvj/9ctXhJoFHNLTD4T+XFojQe13mvO4sw/SDoLMdnoFKj7Q
         oUhd4VOO/MvpkHzDBOlwRzbxRgx9HfMW9X7CIHfa+29rI2TSExfj8QEVTdBRb7WeJC/W
         d25oNckJixivBY7/24mmoZNnuGHdVHNApSY+JAYCKBr0ltoJJ8y+mxikwpAiEuWmTcMk
         rmouHPB+HR/XsIVB++FZ4ML4QbNptIquB/sUKxwZl+23LHSi73G1DRPUDdG9PsF2CDSs
         J9sw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXO6xxr2DcT0XYFkm1kO3UumDaeIgK3y9jlM/sbolrv1NdWnUi+
	40CtkF7k5oHro2aGZJfAOxo=
X-Google-Smtp-Source: APXvYqzPsWOwI588CKRdwYuupLTMpVd+4CHHWMvtx2KAQnzzC0inmBJiC0k960LW08BOxyLvQSXUvQ==
X-Received: by 2002:ac8:1a3c:: with SMTP id v57mr96361899qtj.339.1560809516770;
        Mon, 17 Jun 2019 15:11:56 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:2d07:: with SMTP id t7ls4624373qkh.11.gmail; Mon, 17 Jun
 2019 15:11:56 -0700 (PDT)
X-Received: by 2002:a05:620a:124c:: with SMTP id a12mr91746912qkl.336.1560809516359;
        Mon, 17 Jun 2019 15:11:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560809516; cv=none;
        d=google.com; s=arc-20160816;
        b=oFgsS/TS/C6rp5vIR3TUrqbbnAP0jtvXLJvl2Kv+B2S53SpzGCeg+PzZ5XQxA2ju1e
         /6xCJVSzs6cn8GDal2LXgZgYPNoh9ytBz0Hy4W0uDJgXxS6UapCCsAWaKre8qRkDwBTP
         DOyDAiZI/ex8r/VAiBL16y3MoFiEkpSuWWvc76spokq4S01cG+wXhHjSCWppjCAsFB5V
         fUR7Az5/eWXblmmuuxpyKtCDLLnujLk3GaTNXCJQgugwtivq6FzClhsTfMwPJZj7Hmvv
         ITmU1hUUXpHDGcC2uo/QWXufj20lmyjqB4p7jEwvrh00dHPcxOnohwrlqLTKyoCrMr6O
         t01g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=/VaXSLpZ75ORCB1zbl4hdNQEjbM9Qsyda80h69PRSPA=;
        b=g9qVe9dX9uHL9JTk7zLBVpoY6SDndoSZ1ByCcG5YEF4RDnoRB5ey/MszAKrchi+dmj
         CmZ2MjHH39UqSACe64keFQbfZkXM7xCpRl/n8BW1FtXvgsJ8olOT8wkJYCCKqL+3LUAt
         VlK/SjMxo/AfYiOj3NPCyfug2ckIWhCCEWUrey01mHEDV9plSs/kWfPmTZyYSuEqytS/
         /Zq+P/4hi2hZgfKTRRvhiVCvOQIMA/CqGL25iQMDiHxaMf0tKdGmybVC9Tqp9kXin5OX
         DwvHTjzUyyxjm2+OLkXjWdW/Cb/P8Z49vQyGLHJ0NHCXbiIcbBF42BDrXmvxnXOcnMuU
         5y+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=HsMQvlLI;
       spf=pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=f.fainelli@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id g41si766387qte.4.2019.06.17.15.11.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2019 15:11:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of f.fainelli@gmail.com designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id bi6so4735015plb.12
        for <kasan-dev@googlegroups.com>; Mon, 17 Jun 2019 15:11:56 -0700 (PDT)
X-Received: by 2002:a17:902:8696:: with SMTP id g22mr84220867plo.249.1560809515479;
        Mon, 17 Jun 2019 15:11:55 -0700 (PDT)
Received: from fainelli-desktop.igp.broadcom.net ([192.19.223.252])
        by smtp.gmail.com with ESMTPSA id s129sm12551020pfb.186.2019.06.17.15.11.53
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Mon, 17 Jun 2019 15:11:54 -0700 (PDT)
From: Florian Fainelli <f.fainelli@gmail.com>
To: linux-arm-kernel@lists.infradead.org
Cc: bcm-kernel-feedback-list@broadcom.com,
	Andrey Ryabinin <ryabinin@virtuozzo.com>,
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
Subject: [PATCH v6 6/6] ARM: Enable KASan for arm
Date: Mon, 17 Jun 2019 15:11:34 -0700
Message-Id: <20190617221134.9930-7-f.fainelli@gmail.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20190617221134.9930-1-f.fainelli@gmail.com>
References: <20190617221134.9930-1-f.fainelli@gmail.com>
X-Original-Sender: f.fainelli@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=HsMQvlLI;       spf=pass
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

From: Andrey Ryabinin <ryabinin@virtuozzo.com>

This patch enable kernel address sanitizer for ARM.

Acked-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Abbott Liu <liuwenliang@huawei.com>
Signed-off-by: Florian Fainelli <f.fainelli@gmail.com>
---
 Documentation/dev-tools/kasan.rst | 4 ++--
 arch/arm/Kconfig                  | 1 +
 2 files changed, 3 insertions(+), 2 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index b72d07d70239..a9cb1feec0c1 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -21,8 +21,8 @@ global variables yet.
 
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
-Currently generic KASAN is supported for the x86_64, arm64, xtensa and s390
-architectures, and tag-based KASAN is supported only for arm64.
+Currently generic KASAN is supported for the x86_64, arm, arm64, xtensa and
+s390 architectures, and tag-based KASAN is supported only for arm64.
 
 Usage
 -----
diff --git a/arch/arm/Kconfig b/arch/arm/Kconfig
index 8869742a85df..5c98431ddaea 100644
--- a/arch/arm/Kconfig
+++ b/arch/arm/Kconfig
@@ -59,6 +59,7 @@ config ARM
 	select HAVE_ARCH_BITREVERSE if (CPU_32v7M || CPU_32v7) && !CPU_32v6
 	select HAVE_ARCH_JUMP_LABEL if !XIP_KERNEL && !CPU_ENDIAN_BE32 && MMU
 	select HAVE_ARCH_KGDB if !CPU_ENDIAN_BE32 && MMU
+	select HAVE_ARCH_KASAN if MMU
 	select HAVE_ARCH_MMAP_RND_BITS if MMU
 	select HAVE_ARCH_SECCOMP_FILTER if AEABI && !OABI_COMPAT
 	select HAVE_ARCH_THREAD_STRUCT_WHITELIST
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190617221134.9930-7-f.fainelli%40gmail.com.
For more options, visit https://groups.google.com/d/optout.
