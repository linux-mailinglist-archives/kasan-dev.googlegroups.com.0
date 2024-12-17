Return-Path: <kasan-dev+bncBDHMN6PCVUIRBTV6Q65QMGQE7XUAW6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id D2E989F57C0
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2024 21:30:08 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4362153dcd6sf15401425e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2024 12:30:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734467408; cv=pass;
        d=google.com; s=arc-20240605;
        b=hS7tYnfM45JRSq9nTPn8yj38Bet24azGrKHDxw314UJGBCvZwJfOUZRUPzyt9DIkS3
         F2S7qQjxBUBAEyf9y1/x2fyOFd1IkwASDQsmpLinC6cxfXIIoJW09N+Mk2FNMUubVSwy
         g++n2441+qJwzQhDS5kYA3oQPpSXcM2Rtjowna3uL8r5ulV6ahmHiFApAVxC6oRxpnIR
         pwkFGTQ7flJYC8+aje4O2/J4gRRR3jZSzyKaPoYhUYIkJPD6oPNkXUVTD0uaBak9rKgh
         0ZCoubdMBopl6mVgkw0d59Ju1mFqf+BmMF2YPlGpBs0ItL/x5Xy6Kbzxhp3zNWxAbJ0T
         VJIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Y+YvckKRcE2AyQRANdfvIIudvWfIY6jJlymQP2uxHN0=;
        fh=wA+gav4klW1zNqv2LIcXPfdQNgDwHDCkv99ZUHZ3C2A=;
        b=HnEF03d1E+r9rkshAJjclQVLTnev+z9nmg1wRlkFpasSsSInUCmhgWr551lB2UUrwq
         zica0uDhbRWWwgnWfaZgqGnWLqw6M7HKnXOUMaPys++Nw1ZTbJPXoMIngpc6StQAtwh/
         XloAuatGBB15D4tfnCq/j7sj8R2Z/t/qUwoEiYzCKpGRdyaLlNmsTVxMemW66vw8S1fT
         eUlLCiBRueNcGB1m46BJ/TbG7SvKJWAOJdKZ1LtzDRssuyzZ6pJHrWApnvLtvxgadDhH
         BT9f51aBhMRsEOCZ6MgG3XGsrQ8n7+vmiV7fY8LyVz8QgR3QNqC7jSmdahIvWpIQsL62
         XSTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=jO+xzm3f;
       spf=pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734467408; x=1735072208; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Y+YvckKRcE2AyQRANdfvIIudvWfIY6jJlymQP2uxHN0=;
        b=F8/pgt3qENyUPn6jxSA2G6VD7QxHO6SvmdlR+/HqBsheexeWiNpO5tdCl7lcSSvIJb
         T0pB6O53IXQNWvAMK4s5Hp3BQNKywE2vAzGsCPxyxL4tZfFFjvIcPkLo2tqztbxPEK9X
         ZXgSGlwAv+DZ9+tKmGAKsTPSD+bP6t64OMiZS/amQc+E3I9aCgi2Yi7gdNDdaYiItCzy
         WMq+sQpUZSZUojt7qv7nd5FiLXlcJ4eNPCt3YYHkc9yS0jlvGCmP3eNxSaZvtma2hSGT
         0Sj4SF3KPD/lh6sugqFNOmwiVYhbqHYak455+G6szPMury6tX2kaAK1qXUnoSuQj9OMw
         TSkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734467408; x=1735072208;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Y+YvckKRcE2AyQRANdfvIIudvWfIY6jJlymQP2uxHN0=;
        b=u79sXtS/84WSSb9E1DrlTeH/BN5K0tHtm15t6PRvEq4Ui+IfSCg6Qn2kOVwi8s4uLr
         a02bOHHWTDy8FXC/EhI72vPKxpUvmIkHGqK8pF8F7fPNF0cATsGwq0SjSeB1N5o8RaHg
         1t5YD0tbeHvSjw/J8Y9f+EWZ0qTvSjKn96ekYpkZAlhWSagQSNQywomiHsWaJcxzIOrX
         3Mmpc+N/M6qDHvJm2YmKmcedjRohuYTFyfZVRmDrZgz5hRqNgi7S/OwF1zPnccCIafrp
         9xwkNZTPOnoyg9JddeTuR1PU8JVMCr3qficF6xo5ePx6sake9pHC8QkaATbSXaAUD3hj
         GBrg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXAzS3HP4v1flgwJTBU5S4isSWFyV+E9RyN3wutyb61/tayEYBIxiJVVQb0ATliyNFDd2qtsQ==@lfdr.de
X-Gm-Message-State: AOJu0Yys/8jorMDgq+22KkMga7o6xfCGzPsM6i47/jpd0FKkC4whDaGN
	rszNkJssrPOK9XEO8oyKKUuMGJuPszJiyekTY3FEVz8thPvvNW+V
X-Google-Smtp-Source: AGHT+IEFx1Tn+nvmh9N7hHYQMSS2V9qn6edULvWDQzdA8M7lkPX/1qKSHdi+q/xkpEtA3vOWfct3AA==
X-Received: by 2002:a5d:47cd:0:b0:386:3328:6106 with SMTP id ffacd0b85a97d-388e4d93afcmr172162f8f.35.1734467407310;
        Tue, 17 Dec 2024 12:30:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d98:b0:434:9332:de65 with SMTP id
 5b1f17b1804b1-4362b1a3830ls11994535e9.0.-pod-prod-06-eu; Tue, 17 Dec 2024
 12:30:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWHrWBrsiWsXOFJv4fzM5GXEbOG0JfPxCM1wpXSnHFbanEIT3XN3aD0ChdomhCH+qDAWtrgOHUep7o=@googlegroups.com
X-Received: by 2002:a05:6000:1867:b0:382:5088:9372 with SMTP id ffacd0b85a97d-388e4db238dmr154514f8f.43.1734467404983;
        Tue, 17 Dec 2024 12:30:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734467404; cv=none;
        d=google.com; s=arc-20240605;
        b=ZT/DczHeocNl3ctp0t6ec+mq4zve6Dn+DPhFwyDEjlnCikB6aCQ1++YgHhPmp4v2x7
         xJNvO3Joe4KUj4CSWpAM5LvrDGZxAk3EFnv/EqHjzHvXBfcdnwQMJhWbbMuIBn74N3rt
         lPcd3efx0Iy+AOCJdTvDhGgy3S+/8fWx7t1K/L35EXcGx6hJgvwp0HMLAP3UYpNJhGJf
         mlxWXPQPJDCQTFbaGRFYxPyA4aV2owQFLLktLKKpFwsZcgHO4f2ACB9CDs7+Z/ZjcR+H
         ROt1Aa7U4CQtKmKygwr6TLWIWEJjqOaak3n8IaMb4siRkZ04iejCdpuJQtvz6jTkfBZ9
         Fb9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=V7D68RzS3aDMea5rHMJVmyfJ9DYfvHvk9VNugqZY76I=;
        fh=k2Z8B0SyaWkPc5Fxzj03jgfC6ikcy0wx+bFc5bYaPPs=;
        b=G8wx23f2DybZqyX20Sx3GlSrdEqmIyZYN7PxAXp6+NLPvfBaw6OGYUVylgVwpfuJA9
         pCwZpVLBGUBwND3mV8BaNC0AXNCN0hLz8Bsv8Iu5xRyt9PKXqX1atr3Wk0x1buc/abm5
         CiRDYr7yYd8coA1jOaEpo+Ko6l29r6Sjgwj8PSUYclkQAvvEbhgZ34brub/SjkAu4vmE
         8QGDzlBzoN80bDyFOqV6A9pEdI/kLwBEd8rR5xBPa9EMGM5jOajUEuWBMpr7HXLKdZqJ
         uXhRNyckKpm+ThGR/USmP/GAwh4xA5+Xcb+IOtvsLUyfl/4t3mesbYzGLHiVwiLSzRcS
         Auog==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=jO+xzm3f;
       spf=pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:242:246e::2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43635f65285si1518375e9.0.2024.12.17.12.30.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 Dec 2024 12:30:04 -0800 (PST)
Received-SPF: pass (google.com: domain of benjamin@sipsolutions.net designates 2a01:4f8:242:246e::2 as permitted sender) client-ip=2a01:4f8:242:246e::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.98)
	(envelope-from <benjamin@sipsolutions.net>)
	id 1tNeCf-00000002NwX-1yDZ;
	Tue, 17 Dec 2024 21:30:01 +0100
From: Benjamin Berg <benjamin@sipsolutions.net>
To: linux-arch@vger.kernel.org,
	linux-um@lists.infradead.org,
	x86@kernel.org,
	briannorris@chromium.org
Cc: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Benjamin Berg <benjamin.berg@intel.com>
Subject: [PATCH 1/3] vmlinux.lds.h: remove entry to place init_task onto init_stack
Date: Tue, 17 Dec 2024 21:27:43 +0100
Message-ID: <20241217202745.1402932-2-benjamin@sipsolutions.net>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <20241217202745.1402932-1-benjamin@sipsolutions.net>
References: <20241217202745.1402932-1-benjamin@sipsolutions.net>
MIME-Version: 1.0
X-Original-Sender: benjamin@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=jO+xzm3f;       spf=pass
 (google.com: domain of benjamin@sipsolutions.net designates
 2a01:4f8:242:246e::2 as permitted sender) smtp.mailfrom=benjamin@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

From: Benjamin Berg <benjamin.berg@intel.com>

Since commit 0eb5085c3874 ("arch: remove ARCH_TASK_STRUCT_ON_STACK")
there is no option that would allow placing task_struct on the stack.
Remove the unused linker script entry.

Signed-off-by: Benjamin Berg <benjamin.berg@intel.com>
---
 include/asm-generic/vmlinux.lds.h | 1 -
 1 file changed, 1 deletion(-)

diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index 54504013c749..8cd631a95084 100644
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -404,7 +404,6 @@ defined(CONFIG_AUTOFDO_CLANG) || defined(CONFIG_PROPELLER_CLANG)
 	__start_init_stack = .;						\
 	init_thread_union = .;						\
 	init_stack = .;							\
-	KEEP(*(.data..init_task))					\
 	KEEP(*(.data..init_thread_info))				\
 	. = __start_init_stack + THREAD_SIZE;				\
 	__end_init_stack = .;
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241217202745.1402932-2-benjamin%40sipsolutions.net.
