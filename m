Return-Path: <kasan-dev+bncBCF5XGNWYQBRB65T4DZAKGQEDGLEXMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 529CD1728A9
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 20:35:24 +0100 (CET)
Received: by mail-yw1-xc39.google.com with SMTP id t130sf1070493ywf.4
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 11:35:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582832123; cv=pass;
        d=google.com; s=arc-20160816;
        b=ullFHlQ2m03icB9B1kBuWpnvXHNDttTA6iIAcesmFXbdz9XEoc/ZtmS0VF0wQjSGsh
         vAgDJgDhioSnWH/OZXlG4Xd+UFwgVdZfVlHjm4BEqK6dQqSdU6M+K9enW71YPXqbLzxo
         kbSPPlx+TqslECFTvbYKjHR2u7bGaMXfHAYMXaDULY2edncW4eM3mUySrxi08G+7VwTw
         OV7TXwKn+X5QEBG49XcAETqc/9Xul7e0b7UlUZ8CQY0zacQN7rhj0O1rvKGfwyjYDy5w
         XQGU4mrT4Htkc7uASsVGi/FbsY/ayjkITH3dzKG9Yi/k34sIquZJUJRJB3+uGa+PwBgn
         H1yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=U2Zn30jDiIYsL2HsD2WZGAmYPyD0ibBXQPogYNk0CHs=;
        b=iyYCio0vQMztRfOun/wrw7eUnwEdO0rguMP+5FWSKziWZGLoayGiWZ1llovSfkwgkw
         hS+yq7CZt9csJ3jQjzWgxo/sB2zOVn+x+XuikX/IWjwLfmHy9WyhJk1W3fBItM38gkv0
         7rKLNeQ5O79gkyAXpyRem7eUbptq7VbgmJAcZ0KZ26LrkwVrZRpamsSGXbJY1GWyvMd4
         6V3OkJkUiUKbtBJheNnbJOVmA3zCBai0DSNZe/k3aYqk8wwGp8tXrTqvnnt2fvLorXi6
         QjL0CoJKIDwfpW8zP2NpMWuGvb69hdK44qbdfP0r1Y+vnCJP9odK0/FCT57JQu4ZxONU
         Mr0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="g/0EvsSA";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U2Zn30jDiIYsL2HsD2WZGAmYPyD0ibBXQPogYNk0CHs=;
        b=bCVoDoOlvLUrmF9uJ7uyqR3hXph8QkcFiTRoRk7eFT82L6+FSfHtI2m+S2B0BMr9QT
         JTXz8Fr10SnYRYwDKd2NszGj2lylpo07JE9ODI02A12pm5BJFsbA8sdVgLrSAm5UVMm0
         cRTky6O8wBNNoq8Z/hQNjHGUXA8X1InEhePWL5ITcgoPXbJ91cSzi1L1yVr+wp+FgnbG
         bBWoyvKYi2jK3eGgX2AcLxeDhwc3jMDMLA6ekPT39UUGLrRbgUYkJwmPobtQ6K85mlqF
         tMQrCVgqkCYhUAspCA5UeWsFV0k+vCw6p1Yj5wFNPmHDwjoFFb4+N7c2Imz3oq014JV5
         kb5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U2Zn30jDiIYsL2HsD2WZGAmYPyD0ibBXQPogYNk0CHs=;
        b=ekaZywiyPKkXB6HpA//+CtBFr21aj2QElG2+48qRRwomFhNx6Gy/QGotr+gggdToZO
         twSprwtPTY4qsGjLzOnNrY9vw+V23z82voHHeqNk2tMqaX5OYuK9mqfd9QGIQl+kctC7
         1I4679PeHYD9tTlHS7SWcXyznHUHUpJEfFEzewpf/ddkoouogHiX/N+m1RZClAWy/ZTo
         PlG7S3+FCa/DVTWf3p/ezZVw0c9fy3r60ff7ucMok31Ng2DuUQNSzTw/IojbAfz7qVx8
         L+42NDVnSE3q07a9usPRjWej1jwNU2NiMBTUsl4Po59qneQE0x8DFuKYhNDbjuFrwBGh
         q2Xg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV9zrb9OD3+frjdU2EpKfPB8BVI2MmcfyPvKy56hKWKglr7WV8c
	NbNxgs3R5o6mU9sgZfR0NV0=
X-Google-Smtp-Source: APXvYqxgm6WylX4BRyFbr4O5KuTGrxiAMJhBpVt4cV4hOhYg/iuc+YavpElRYLMDY0pEFwt7uLQyGQ==
X-Received: by 2002:a81:72c3:: with SMTP id n186mr1022421ywc.342.1582832123319;
        Thu, 27 Feb 2020 11:35:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:1bc4:: with SMTP id b187ls28875ywb.10.gmail; Thu, 27 Feb
 2020 11:35:22 -0800 (PST)
X-Received: by 2002:a81:7015:: with SMTP id l21mr940381ywc.425.1582832122880;
        Thu, 27 Feb 2020 11:35:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582832122; cv=none;
        d=google.com; s=arc-20160816;
        b=mzGWF/8tA62pVwRfmvoR5OM74FS0S0vxMUGXc9F1X1yyeSOBXvDsFpaDG/4BRcGFoR
         DPTl00ItC7G9NDCWD1HBDEd7j7RVjJHoPrVKLi7CbeW+t6vtJWDGEqLGwBOSZld5BojN
         2gk+dwj4630cwptafrlZSbOS0m4KHI06LDLDCvnYNV4LPVkXZDpFHoKLWtC5FtijKmxK
         +cyOwPQ7Q88oRpLkergbUTHMkZLcymcP7FYXUkZAt/6izDLZdeMKQO5kB+/hpk9RtelU
         efQgxJ7FMO0kgNuU5fNd1RE4u1xpnU8wIAf8WGDE2FxVSdv0JI2tZN/6AYNZt983W9Et
         x1xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=46Z0N6nNFPIgM2OuwNgkHRjYe659IsqNoWw8FG0hdrY=;
        b=RIjj86Nv7X+FNKy9k05qGcZtTRUVyishFkVtRakp2h5EidOuDwrHytX733C/RtE5cr
         4YBzIBqpmQjD1loy4DVRozGk3U0OXgOiHWbvCdd/box3qFaHZdrqnltZt9wCCMdTb3Ql
         Tb+zwKvLAYGsX+OcBoX+LGoZBgMxNB2sRBMiw23vGJ5hs9i6Bf1+M1dYV5/qwhOCnWVE
         FDyHgKynB5FjLfOBc3PVXbDA/mCGBw+BRM3hYlFjJ1j5HHZqdTwxtWbj00aGJ0uESG/8
         2hkfqJZhnzexIjym7xTaqiubun7RIGf6isL6N7KTk7r2QGVLBcYF6aSeBMbzu/Xho0v3
         G8xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="g/0EvsSA";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id 136si22957ybd.4.2020.02.27.11.35.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 11:35:22 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id f2so3558378pjq.1
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 11:35:22 -0800 (PST)
X-Received: by 2002:a17:90a:c24c:: with SMTP id d12mr520844pjx.113.1582832121953;
        Thu, 27 Feb 2020 11:35:21 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id p18sm11620140pjo.3.2020.02.27.11.35.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Feb 2020 11:35:20 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Elena Petrova <lenaptr@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com,
	syzkaller@googlegroups.com
Subject: [PATCH v5 4/6] ubsan: Check panic_on_warn
Date: Thu, 27 Feb 2020 11:35:14 -0800
Message-Id: <20200227193516.32566-5-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200227193516.32566-1-keescook@chromium.org>
References: <20200227193516.32566-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="g/0EvsSA";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1043
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Syzkaller expects kernel warnings to panic when the panic_on_warn
sysctl is set. More work is needed here to have UBSan reuse the WARN
infrastructure, but for now, just check the flag manually.

Link: https://lore.kernel.org/lkml/CACT4Y+bsLJ-wFx_TaXqax3JByUOWB3uk787LsyMVcfW6JzzGvg@mail.gmail.com
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 lib/ubsan.c | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/lib/ubsan.c b/lib/ubsan.c
index 7b9b58aee72c..429663eef6a7 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -156,6 +156,17 @@ static void ubsan_epilogue(void)
 		"========================================\n");
 
 	current->in_ubsan--;
+
+	if (panic_on_warn) {
+		/*
+		 * This thread may hit another WARN() in the panic path.
+		 * Resetting this prevents additional WARN() from panicking the
+		 * system on this thread.  Other threads are blocked by the
+		 * panic_mutex in panic().
+		 */
+		panic_on_warn = 0;
+		panic("panic_on_warn set ...\n");
+	}
 }
 
 static void handle_overflow(struct overflow_data *data, void *lhs,
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227193516.32566-5-keescook%40chromium.org.
