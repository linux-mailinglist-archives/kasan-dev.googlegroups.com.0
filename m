Return-Path: <kasan-dev+bncBDX4HWEMTEBRBT4ASP6AKGQELFUHTFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 31F0328C2E0
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:05 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id e6sf6846371otl.13
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535504; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z83doh/iflGg3VtojoJGO0/VsOhjpV7Xwwoo34r7+TX2tqNWvR5rGkfeO8MtkN/CEr
         1mRvxFpsxi7FPKphzldjw3mXrku5RMyhWLcrB7oMw6UdcuyrEpTmcYpAQEVxepu0Mvf6
         DYEoa0gX8q11FStC1JzcP0Dwee1nCUw5boKlm45az+NtpcFQbzPffZ2giNX/52NqzqFt
         V0QvWdQCuNajETPGLG6BiCofK1mrdxmib/CN3CN0E79KuPFevdp8Dy7c6PSAPl6Kwfrw
         aM6kfr+gNffeJ+8NAiAjclzoT2um1oya000KSLwQGWaWmiINZci8y0qUc4yCeLNX7a+X
         cjnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=nOOFVcz0eKkeP4Pvd8nObaGLUf15XoGBR3any0iFHtU=;
        b=UT+AXqm/Nqz4Gew3n3Nk2A8rY+zUvbk3ZtATIWaboh7mBl5VjIfIiya38YUmGuu1iW
         GexOVHjnTtLJbtz9yCZjVVxKS5WQX6SEEauqy3L+RiI3f3xdcHMhd67E9I07cFus/UyZ
         J4zpRqdD2Qr9nBdUDepz+qeIxHvH7iIr/TmzadORKx+dZlMOMDYsG5nL/nOblJVTPohK
         HosgfrUblKmCMNuO09idXhcb5ulXZRDhcP51+P+pyjHqADtpv/VEJmBgdIQk56S1SSwG
         cGykxb+FffGtf6Xk6HYCvQkW0qanVqouDkbMyln6CYPhSOT6UdfUdLT2K5mY+cnZd4uM
         yNRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s25bdqcY;
       spf=pass (google.com: domain of 3tscexwokcemfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3TsCEXwoKCeMFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nOOFVcz0eKkeP4Pvd8nObaGLUf15XoGBR3any0iFHtU=;
        b=Zo4LuCId7liaTPRhGeM7rNlXaVtu9pb9ejSRPYauDoElFvgllrpLNru9pDB6/C7ab3
         tKnMvweUr1EJ6moZMEUPI19m32ktKtm3bL8tERP9pJRe5OXgTiA0HzgU7uz12zuqzFH+
         jWLRcv52Z/ukCC01rfrFddcIzXxnMJ02fibJR6BJpdEMNI8WJaZqv8B7lAfwlsjHUGpA
         Tca8DGH9G8gpc9MDADCvxQQFfCGVt3oDxPZHDO13eyeAYq/DRAjJjmX/u/DDcU3PE2bW
         uKfCkFYsIEWaVwmGvDhcbizGHy97RgqmwXmWtVEh+NAuhWgaAEi8puIsRwtaQ+x2KJRn
         UUsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nOOFVcz0eKkeP4Pvd8nObaGLUf15XoGBR3any0iFHtU=;
        b=E2Y9dCUw0x0r+sL429L8JtJL8tKnvZlxfUyIBCgb8YNvWQldS4SkyI4/guqaQhJ9sU
         uX7wFLiff+Cn6OhRINFZlUNsm+n/AAKZIW1H8C4jFI7rFTZL3JGWnfwoXfhgM1Dtxl3d
         rkDOpm8JATjw30MeKXwm84Jg96WIBGplL+4SCwzLgyNag+EIrqcYRat06ahf+dFb8t0p
         IwP6xJuYhN2kn91I+alVKYaOjvr5L17i6tmAlJ4tA/00Orlwwm1Rxn6J47D1pg0ceCjR
         FcHvrNrQo3lmhA/az+4lsju2+SQRr07DTBFUPGDy2jRfavOgH+9pyMDNS1O+YA+2E1E4
         armA==
X-Gm-Message-State: AOAM531omgB96hgTYUdItigEG/MKUS2Z3tZKqjv9ih/Vuqf3e5ZKZ4jX
	imtE+dmtzzzKsgjHjyXVB5U=
X-Google-Smtp-Source: ABdhPJw4QkxcT4LL0wmMHSCLe//hv9PEC82or1440ZwX4lTwrlq0MhM6Jd/JIwEYpHzKttiq+ihD5w==
X-Received: by 2002:a4a:ba10:: with SMTP id b16mr19284047oop.75.1602535503729;
        Mon, 12 Oct 2020 13:45:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:c1:: with SMTP id t1ls56382oic.7.gmail; Mon, 12 Oct
 2020 13:45:03 -0700 (PDT)
X-Received: by 2002:aca:5f89:: with SMTP id t131mr11884482oib.32.1602535503392;
        Mon, 12 Oct 2020 13:45:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535503; cv=none;
        d=google.com; s=arc-20160816;
        b=jjbM6VRDhdu5RcYS+ucX2sJkzQQnNucxMIx7lLmmdkfZ75B2t7IiFY7sxQpjku3IqQ
         bsFjbGkGXpWx5+ouPwCFvuZ8knp/VS4KHiFYE1wlOr1b8ZKzG23iYDlBVmkbjKUXqlns
         kmJaBq5oIoKUabiyCSCFi6iKSrLN5RwCZWlzVGGEKo/Smbk8LQh2pU760Bs545gD9IoT
         w4m6Nnsi4P8g40QoPIvqwNho1UHfzwd54h3e7TUflnWOfVmLiDtoRirN9gKe/WpVG5Re
         aMW1ODvLRbqysSMWgcEL0Ecebq0eDohCAHYh68x7Tw7H2xG2nq+cfmzEBQ8g3xhwbFj/
         xd+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hYhPlgHhKognLzO8gXB6+9AazEuqabRApbqRCWki1UM=;
        b=MpixyQBg1KeF2umuV+GP75uZEV+hJDlp8ybHqT82cchr20zMF3FEbb/pvyfa0J1DAJ
         8ZmCvgqJWXgVIuzcxPefzE4s3dmodWCuxivgMIyZUn9Yg0o7wFC25d72Q7o8dTzjpY5w
         BNAX47omYqQX3nKzys197zK/2zZaVQwHxu8wafatrz3Zn0k931l4yUr08MgUVfmqFs2c
         oT+fJxqWRZR8/UX5Y1yNfCBvTc0YukAmbnpeCSmXGi9/Xo+Jx/1cVZ5wcfLvooRx+3nX
         fPNylXKvDn7OLI6pMmJmS0TRx/XPenNRbM6m/npnRFZQ1qeu9EPibhwn+687wXEnOpW/
         psAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s25bdqcY;
       spf=pass (google.com: domain of 3tscexwokcemfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3TsCEXwoKCeMFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id r6si2754500oth.4.2020.10.12.13.45.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tscexwokcemfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id i10so13576150qkh.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:03 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4150:: with SMTP id
 z16mr21553789qvp.50.1602535502842; Mon, 12 Oct 2020 13:45:02 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:10 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <c4ff07654478c1ba427b0366122a1ebee3f46387.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 04/40] arm64: kasan: Add arch layer for memory tagging helpers
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=s25bdqcY;       spf=pass
 (google.com: domain of 3tscexwokcemfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3TsCEXwoKCeMFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This patch add a set of arch_*() memory tagging helpers currently only
defined for arm64 when hardware tag-based KASAN is enabled. These helpers
will be used by KASAN runtime to implement the hardware tag-based mode.

The arch-level indirection level is introduced to simplify adding hardware
tag-based KASAN support for other architectures in the future by defining
the appropriate arch_*() macros.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
---
Change-Id: I42b0795a28067872f8308e00c6f0195bca435c2a
---
 arch/arm64/include/asm/memory.h |  8 ++++++++
 mm/kasan/kasan.h                | 18 ++++++++++++++++++
 2 files changed, 26 insertions(+)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index e424fc3a68cb..268a3b6cebd2 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -231,6 +231,14 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 	return (const void *)(__addr | __tag_shifted(tag));
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+#define arch_init_tags(max_tag)			mte_init_tags(max_tag)
+#define arch_get_random_tag()			mte_get_random_tag()
+#define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
+#define arch_set_mem_tag_range(addr, size, tag)	\
+			mte_set_mem_tag_range((addr), (size), (tag))
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Physical vs virtual RAM address space conversion.  These are
  * private definitions which should NOT be used outside memory.h
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ac499456740f..633f8902e5e2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -224,6 +224,24 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define reset_tag(addr)		((void *)arch_kasan_reset_tag(addr))
 #define get_tag(addr)		arch_kasan_get_tag(addr)
 
+#ifndef arch_init_tags
+#define arch_init_tags(max_tag)
+#endif
+#ifndef arch_get_random_tag
+#define arch_get_random_tag()	(0xFF)
+#endif
+#ifndef arch_get_mem_tag
+#define arch_get_mem_tag(addr)	(0xFF)
+#endif
+#ifndef arch_set_mem_tag_range
+#define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
+#endif
+
+#define init_tags(max_tag)			arch_init_tags(max_tag)
+#define get_random_tag()			arch_get_random_tag()
+#define get_mem_tag(addr)			arch_get_mem_tag(addr)
+#define set_mem_tag_range(addr, size, tag)	arch_set_mem_tag_range((addr), (size), (tag))
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c4ff07654478c1ba427b0366122a1ebee3f46387.1602535397.git.andreyknvl%40google.com.
