Return-Path: <kasan-dev+bncBCF5XGNWYQBRBANU4DZAKGQEAYCXWQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id D779E1728AE
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 20:35:30 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id s18sf197368pgd.13
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 11:35:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582832129; cv=pass;
        d=google.com; s=arc-20160816;
        b=GX0f0iPk1tqALW0pWxUoLJ8erZHEewfmNluVym4j211gWoyjT7gAn3FDtr3ToYQBCy
         3Nw+JNx0JvgcpignoXj4zCTwQlVCimzKUTwKLxFDbgKvgiVl4djNvR2btAHz2kWEQ1Jy
         xK+H0E4fg5Q5sRPXqGPPKXiBDlq7ePtw1iXvbwS3e5lyTSaJ6evHXGnevCJQlwUS5zL7
         KyQqOkhdefgjOyebRHETG7xebcv//yCQWI79v2fXb6m+1vVBAWqAHgaSr7aFF6NDMXVj
         sUvdlyD92tavafZJkVu/FvXZKQlJjvbAP4xDnrC9lqfn0jVtlFTbwAKrjo8D1tVFPaow
         gYnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cgwwPq1Bo6fe2m1mlNebJY6n2ThTf5WL2i+Fx2Cf/Tk=;
        b=L2/kmcyu7rdP6deXSYyMXgLTKDrLJuNmwtIsEZ3+WlK3b4H3QeD0K55vawdEwTdq0n
         tD6Qa88W9VmGNsAltxv0YlE92REVyW1jfZrrJgIZymjdxIU+xPlKOeBtIOnECNqh/7za
         f++lA+W9WsrizpYl+cUvcaUSFsclAge3m3CYgftvvD28CKb8rhW48KTsLwy3ngQJzVUa
         hZbfJ5ElEuTQY3fE2uTydE0KIumJT0QBma+BPhSv517iJNanHsb2ekUmu2L3Aq1+FrzS
         Nst6Fz+1rlmXid566mD/tznl6mtj+H77OwdcPK/gr4KU9OezQ/2c49xm1gkk7xSix1S3
         T6Vw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=YBkqK4RC;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cgwwPq1Bo6fe2m1mlNebJY6n2ThTf5WL2i+Fx2Cf/Tk=;
        b=lxy7FSieNjBCDTZ4ef+KhoNdrJ16jQyUHKDp+3G74/BkhRWyNTs/Zb94mB08G3WHMQ
         +tDoQEyJ0nCOoP+iC8QQN/VNvwrBMQCVC6E7tExyCkVpSiR5uMV9mxhFWcMPDQUzfq/O
         9ZqR82RMfNheLjn6YSHsi8tcBQw/32tV0O3L4sB+hj08GQgbWLicfyWARt4qUdiu0JIs
         xsvqRIP4vZ89njI1jICFv+0mk2yrqEaMT0t1U/9pRbdD47MT9LhWtqhDturGY4KDKw4d
         /IIAq2rBypYabvfN2hxruCTvO9iKBZChyB8ZnfcRWkrPr7ff9EsXFclGJLcSHG0APkA3
         pfSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cgwwPq1Bo6fe2m1mlNebJY6n2ThTf5WL2i+Fx2Cf/Tk=;
        b=cNSwCoagIKzE8zKRuXfuM3Bih07ll6Vb+QRBJCV0KQZX1kxk7y0uPZwiycQVa/SNnU
         QQ9nAcucNzq7vjjUuWKuvs5viZwqvVDdFwotah1c1Mn6zsLKpCgsRO9las6JhxM2OP9l
         dgZ0kgXW6FrJIAFjiKamiNspwjPvtpMBcpoebN8hQkVD3HtOHBeJIkkJOBy7gk1l+/pr
         fE7AxzgLhYxu/4y/AH/zfBaN7bkkhs96qTO3l0v1z6WBxu5/XDTlHIcoCTrXKbK6rZNH
         9t9NvEDugKItkA6lIl6n725rbo/hap7q0MoRCD1eJvbFkUYLGRQZY149sh+QQc0R4PE7
         k4nw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVR93ljNSic4xH/5C3BcJD13h1lvZ3dlW8QXeoBkYfzCxeivFag
	IecAD5MyFfUXfrHdZiwHDYM=
X-Google-Smtp-Source: APXvYqwxiQ0SAfJ+C3mx5EAfeDzsGv2X/MkHRWUkbE5lt9FVKaR3dgmlQfiH9Do6ZThXlbABd0Ev2Q==
X-Received: by 2002:a63:7c48:: with SMTP id l8mr894859pgn.150.1582832129352;
        Thu, 27 Feb 2020 11:35:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:745b:: with SMTP id e27ls144771pgn.11.gmail; Thu, 27 Feb
 2020 11:35:29 -0800 (PST)
X-Received: by 2002:a63:fc51:: with SMTP id r17mr883333pgk.292.1582832128948;
        Thu, 27 Feb 2020 11:35:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582832128; cv=none;
        d=google.com; s=arc-20160816;
        b=v3QkYFY6E7plwp0TGwzHg0pBITQeXE1+v6E/z09U8tq59IYm+/Ygnca6rt60oNjKuX
         jc++fQhHAyy/wUWA0u1WIOwYO+gmo5CEasC781NJBGp4xre6WFlTNMArYkL5cAIfIoKV
         kA9rOwvgHrvoniobwSlgMMvv9xObWvbiedFN3lEqm+H/BmPInAWfTmhCzOrkSEbaw7SO
         f5Oi1ChLGl/TDcq/YxADszZE1WSN7giA9AT2MApwI47pgUtbSV+ZpnypN0Y2jAZOU2cz
         qmmbVjJEDaFbP664Vkza6YQhxmE/3F0vn0XGRO/JSTp1AEZDpsuunYGv/cYypRsgcnY6
         2M9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sVbVapbdvm9D9bZT8RLizJdch6+5SIEY/KYRYQVG8Tk=;
        b=Q6IhIOYJ8JojuVpOLW3AovYxetdpyhSEINyOEu/mVJyfTufiTx+Uff9tlvV/axfCwL
         zlrQP9ob46hB6FK5hLgOhCYVFs55LWZDen5Zr09/gWk81QXH4PtfGV02xoolvtCgMOpI
         c72Qa7lBjk+50xziJLZ8eHddC9wit+nrHU5XO8rodzr/Dr7LbVlBDksvpZLeWdAXDrMI
         KriU1JTYWm20drjFkte/cW5dbdIjTyZmrMeHfcEYYGOy4a7Oi0EDFMJBoiBtskpHplHh
         5bhNsokV9chDnXgexpamsN6B3fSmPC709AuT4liqKT9v+Fai0squEpwuaUDMslZK6YjP
         SFXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=YBkqK4RC;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id e3si9965pjk.3.2020.02.27.11.35.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 11:35:28 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id u3so197666plr.9
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 11:35:28 -0800 (PST)
X-Received: by 2002:a17:90a:3266:: with SMTP id k93mr527984pjb.23.1582832128663;
        Thu, 27 Feb 2020 11:35:28 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id c26sm7957064pfi.46.2020.02.27.11.35.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Feb 2020 11:35:27 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Dmitry Vyukov <dvyukov@google.com>,
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
Subject: [PATCH v5 5/6] kasan: Unset panic_on_warn before calling panic()
Date: Thu, 27 Feb 2020 11:35:15 -0800
Message-Id: <20200227193516.32566-6-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200227193516.32566-1-keescook@chromium.org>
References: <20200227193516.32566-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=YBkqK4RC;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::641
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

As done in the full WARN() handler, panic_on_warn needs to be cleared
before calling panic() to avoid recursive panics.

Signed-off-by: Kees Cook <keescook@chromium.org>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
---
 mm/kasan/report.c | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5ef9f24f566b..54bd98a1fc7b 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -92,8 +92,16 @@ static void end_report(unsigned long *flags)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn)
+	if (panic_on_warn) {
+		/*
+		 * This thread may hit another WARN() in the panic path.
+		 * Resetting this prevents additional WARN() from panicking the
+		 * system on this thread.  Other threads are blocked by the
+		 * panic_mutex in panic().
+		 */
+		panic_on_warn = 0;
 		panic("panic_on_warn set ...\n");
+	}
 	kasan_enable_current();
 }
 
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227193516.32566-6-keescook%40chromium.org.
