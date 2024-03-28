Return-Path: <kasan-dev+bncBCXO5E6EQQFBBU76SWYAMGQE42ZSSRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A2698901C5
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Mar 2024 15:31:49 +0100 (CET)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-60cd62fa20fsf19747197b3.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Mar 2024 07:31:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711636308; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wf0QL+wtVkCQzBEDpX8b+qVJrZf4SPIad0GtsNAsfWGlilj35bbrZwotFrV3piWa4n
         T40iVQLkNyVAwLXbpTPo0yx1nwXTZ43v7RYiG5TeDEkV5McQliFQvbV6bDz6s34GLlnI
         R5ZL8I4IuCv/2fgRHV2fN6vFRwOujp4hTtiD6Q0QyCsDyMpICUdI2rEZdvy9wza4kxLG
         46K0xM6AZW+Ky9Aqz5w0STJEvXzyj3tKEfmCH3XDm1LZQeP2LqJYcuxUWRwdwsg3lht+
         TvrwATzaDT/YgEaraaoy7+aikjzgWt5SV52I1n8Wgp7l2rn8UVeSzajPMULVzPCH4hFv
         RwBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+gMe6b5bBHfe2pnpWh8ctUVe3c4hrBO/lbn72I7uLb0=;
        fh=1Advn8r1yHOyKB5DGgpFElO5++alyyRDkap3UQGoRUg=;
        b=SjVknLrU+GSAH9d+CoIWoITf1z8Y/iJzeEESoTrGos/8BKHqHf3JPJaKDtW/NO/a52
         FCoKeMVhUIyi+9kkFraWb5zVBhK5yeCScOUyF0OIKTpKNVCI9MlZZdoNs5vc7BKF/Ylv
         flzaXzXl9f9KF+mzeRJPn6d4+F3zsvcLqaUHk8HqXT3KBMF6iJYecTsNR4TB2n2CEEWz
         mVXUszLsx8GZm4gyZlXXa/p1Pb7Qk/k0STk7ScF+sAGxw/rby+2UWRPsJKqY8MggtnoI
         nnUQrYzeboOt84sf2UbOeYvuFznS5oZacbpbl/SZNYjyF4IwgfKyuTKoRqepkl3VjShu
         a4Qg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Dz5xPjEt;
       spf=pass (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711636308; x=1712241108; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+gMe6b5bBHfe2pnpWh8ctUVe3c4hrBO/lbn72I7uLb0=;
        b=Ukb3wAkEq/WS6lAexkh2fPadgyk0AEy5PELDIKUj6HPrhIaIzZs+NLhDqKiZYAdY7g
         U5BXxdmJ1lpb5mUDOBgSbSODpU/3BfyJtDW2tsQ/mXY5iGo9/wXaTQWAND7ajvd73Y4/
         JUp1rsLxJNbAwHj4YqV3gy9i6kb8Czet8a/xBq2DJC1l25AtoAjTetbU/OMofUuvfdb5
         MJ/gOfMTr2vXBGkdPUJ0jKpJCJ1gJSCzB+EZdtOLqH+6DTkOj4NP+y97nT4OT50WVDQO
         lMj39G1msei6uzXI5pXI7w4PB1/Ylqz/GJA3hzLoZz/kovNu7IoD3/3wK3fLmrq75X0Q
         jIsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711636308; x=1712241108;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+gMe6b5bBHfe2pnpWh8ctUVe3c4hrBO/lbn72I7uLb0=;
        b=dx1vZQnSx3a06QNaxJrfwMVw7yyuTfN1slhg0qEKNHhQE2ySctwEaGTSQYrOx3Rq1/
         BE9AvQ7uqbscFbZhpgBF/oa15cjLX3u3P5ALyVGeygEM9tH7II3bxqJCyM32GXXF0UTB
         UuxdYwqr37kWhyjFmf3oH+IqkK3t9bSDH0/Naa/6S+wpUmUoxBqdY5BuxniS6xxsVmHh
         vh7bQINYJOVK903iw3r+iiJq3U4nxmjXIO6fgPmn+ZzrGQwK1SafwBE8airuHJXHucm1
         lOHdGISCxgvYs74RjWovR5EelizjXfPZCfshRtP/SJNs0Mhz01sjv9jiLs+2PHUEhn+m
         QS9g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXJdmt7iE5Vr61W8FjDCOEbV54DMDTXASJD67FNuE9VWWh4Ti5qpR0CI/5iE93tzGD1yqGdOJt6IBJyA4J9gD851HDuimeRYw==
X-Gm-Message-State: AOJu0YzGT57nI5Q456+zCnWHSiHNWW/TRid7jMVUHOKv91se6J++2fkK
	6FRewyX6ZYDMI3xKPHTUkgaC0qzyR8PWajM4F+CxTMHUr+vUNqD7
X-Google-Smtp-Source: AGHT+IFrWI6F2nAh/NvQkyaAZguFx3XRLWdUTG8doaphB7QlESm8HztFuu0FDJSmE2AUAlZuiR9WZw==
X-Received: by 2002:a5b:b0f:0:b0:dc2:41de:b744 with SMTP id z15-20020a5b0b0f000000b00dc241deb744mr3112999ybp.32.1711636307541;
        Thu, 28 Mar 2024 07:31:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2f4d:0:b0:dcd:a08f:c832 with SMTP id v74-20020a252f4d000000b00dcda08fc832ls1469027ybv.0.-pod-prod-04-us;
 Thu, 28 Mar 2024 07:31:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWg/xT7vTmSzaQEThQrHr2wRNxDOe2Wrjr0bprvxnSOr5IiP4ZunfydTBh0sDSRUW0E/L/BOvwQFOlWALUpv6NG3MKqLG8CMRKYeA==
X-Received: by 2002:a5b:ecc:0:b0:dcf:56c1:5a12 with SMTP id a12-20020a5b0ecc000000b00dcf56c15a12mr2877738ybs.38.1711636306524;
        Thu, 28 Mar 2024 07:31:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711636306; cv=none;
        d=google.com; s=arc-20160816;
        b=0zRTyNDMAmzkNDDrZqMPA5Qibs6qtuqzbFIl9rH1xE/+Vb5m+roU5bjTqo5YM2Zv7o
         bjGVtnRn1K+WKdt0AGtg8w5TnWcPQOB1WDIswJoPJ7PYrhKJU464hZq3c74A/y4VF5BH
         GJlR8vg4+ys30hCHDJ19v1zzeoScQeFUPc6OjIOFSjdEOE/kxlIcvVZUpDkE+WajYkmA
         CbYE6jTkTf5m2FnEa/lJVNUYU2UophxWWJa64jM/i76NbGyZo0lRl9gTRtkGq0GyoDP4
         4kb8k/qiA/UdOY17Rds1a7eANUyayTjfGD1woIWVayNDgmlNgIAvKwIitOJBaTw47ZWx
         gd7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CxieiJHF4jJtoTpnhDJLCD2Sfa4iPTUt9mMg8YDG6n0=;
        fh=a8JIY2S9OCpQKjzaHICHkhjC7cIcirdgPz/FTl/p8J8=;
        b=NkqGqP6UmNU+31O5wt+X0VIo8qu4HkQnxPnAVGGxzHoU0ZGqpWdRsyEbKwLPSgrLyo
         sLoh8Q+jGQm86Fu4DJkMb9cNuD14LmQ8RYFkCag/GS+BZXdc8WaAf5/vHwhY4aXbGEhN
         /dVaOY3FTHDKNPouozqRnifM7W//A8PMw7Z6+nYhjtmZvUCKGJXs3D10L4vKWIiZZZdJ
         8FVggz/HHo7Hvuz3k90MRqQfwFq8HWeQxhCE0ZIDSGO3E9W0+3Uc+jFlUsJ5yn9+VCMz
         HkKcD0lXhzkmBmelxPhEXiqxp8P+d2RfKeCB7U2gLLk6LpJrIoPP387Weyof4lCofySz
         7KYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Dz5xPjEt;
       spf=pass (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id w77-20020a25df50000000b00dc619c1f82fsi112242ybg.4.2024.03.28.07.31.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Mar 2024 07:31:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 379E66179B;
	Thu, 28 Mar 2024 14:31:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9D19FC433F1;
	Thu, 28 Mar 2024 14:31:42 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: linux-kernel@vger.kernel.org,
	Nathan Chancellor <nathan@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	llvm@lists.linux.dev
Subject: [PATCH 4/9] kcov: avoid clang out-of-range warning
Date: Thu, 28 Mar 2024 15:30:42 +0100
Message-Id: <20240328143051.1069575-5-arnd@kernel.org>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <20240328143051.1069575-1-arnd@kernel.org>
References: <20240328143051.1069575-1-arnd@kernel.org>
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Dz5xPjEt;       spf=pass
 (google.com: domain of arnd@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE
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

From: Arnd Bergmann <arnd@arndb.de>

The area_size is never larger than the maximum on 64-bit architectutes:

kernel/kcov.c:634:29: error: result of comparison of constant 1152921504606846975 with expression of type '__u32' (aka 'unsigned int') is always false [-Werror,-Wtautological-constant-out-of-range-compare]
                if (remote_arg->area_size > LONG_MAX / sizeof(unsigned long))
                    ~~~~~~~~~~~~~~~~~~~~~ ^ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The compiler can correctly optimize the check away and the code appears
correct to me, so just add a cast to avoid the warning.

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 kernel/kcov.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index f9ac2e9e460f..c3124f6d5536 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -627,7 +627,8 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		mode = kcov_get_mode(remote_arg->trace_mode);
 		if (mode < 0)
 			return mode;
-		if (remote_arg->area_size > LONG_MAX / sizeof(unsigned long))
+		if ((unsigned long)remote_arg->area_size >
+		    LONG_MAX / sizeof(unsigned long))
 			return -EINVAL;
 		kcov->mode = mode;
 		t->kcov = kcov;
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240328143051.1069575-5-arnd%40kernel.org.
