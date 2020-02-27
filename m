Return-Path: <kasan-dev+bncBCF5XGNWYQBRBPM64DZAKGQE2752EDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id C0295172803
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 19:49:34 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id w13sf111970ply.11
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2020 10:49:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582829373; cv=pass;
        d=google.com; s=arc-20160816;
        b=dTBkzXBHC/avA5PxHQM3Hu4YZmciJBXWLlW687g05akKtF+HSqImJixlbC2e6tqgYs
         4DzfNhlQMX+C1QNOD6q8//dbBcGv8QsS/s15kEDpIus6f/cvFzY5g3J/3E+Ab53CeECU
         OP/hNPVPon8vspkFwhrBjn3OtHLUOJsmDVUPQLzzcpew07zA+Si4RCDNxLrf4PKWBz/x
         W3VW69tcJV9p2kkb/YgPX56gydzfSmbm2TI30y+QD0i7XtCkg8RDvlbkvHl2VkyN5Uu0
         PWXwOFeICe1r38iLkzEFcSd/dbI/OZXXlV/qNkBpqybM4Ohk7yD4vcw9+fjba4/DhqQ4
         BsPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=AkIrGHdYejvau6S5dBnkRrHg0F+DcxgSdQzwbCMD2WI=;
        b=lHxHqbN6LZDwuL4G2mZfYpUVEd001HSbn4vgUYCEvskHrRzJHA8idQZAOC0hnuYym0
         2UaThFYal7BYxNYlMJ6kYqLwbNLmNtC5rKQtF8CSs1g5wMyeWgFNYHhLFYtoDok2AsMO
         kJUBHlUvcVqdW3/V8897xuLeuspOPBuC0HiQxmAZ69v+LKUpwjf+9Spm52MSIMayuD3f
         M6PukcGLAZqZYPVPykOtVdaTvcsaRZGRq5R1P9M60Co8pTBnMQkb1DJChImMkhRYwgjk
         AwYRupDJPxgWN8w+ki2rr5w4p4yOFjt6GeBsBJ9XD8/rnApytqrnjDxP/hYuwpVINyCE
         /b+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=X5i1lW7g;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AkIrGHdYejvau6S5dBnkRrHg0F+DcxgSdQzwbCMD2WI=;
        b=O2leeuHO5xC7cXSBp6s3vqsrTRdePnSTUOEpbhFcWrfggs7ahcWMrx9McQbeV7x5w0
         noZ9Pe1Eg/t9493q4L1NHn0KMOmcDmBwKJpAD0Js8iYtJnfo/6CKT1FNuPz9Vj8PZTXA
         o2xySVZuaKRprQMqpdcQudBr+Y2qLyUtTAd2DIsQsL+eRCyernFxE+U8hUylW+Sw2O/Y
         0jSn7GDSlx2qzg4nimAUP6CyGXOexO9Embq56GiiTassJmhHh2agJ20MEiIRkzvtKM6W
         tLLLg9pJndEeTcByiaCydA0JUy35y/89uEuLObKxmU/XSn4kzJaSMUdq9jl1Mk6yTFav
         Bn9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AkIrGHdYejvau6S5dBnkRrHg0F+DcxgSdQzwbCMD2WI=;
        b=S1qbk0trR1UEM105jp9Xf/BDBmRpLkgpRw8yfNSbUCUJ+tNWnTeQcLBKUHDLZnfLv2
         D/Zw4WpTyyCXicy9GuMbO4O/2o2LLe1CqegF1Csk3w3tkXxIf03ESppIPeFnBp8qqZqY
         OTbRddl/fyX4yUvqMzbQP/caia2OyOPAvI0lgG+Xa04ZwAbSKUMZ+7OpYiawLwks+/sw
         WgnPteFsnJRVeFDtUpdMk95DbviI2zMru3u5BlaRVi2TGIuIC/NOXGESH84IKo/wB/eg
         8YuzK+9XCQlhuJUD49uugdfnW3XuOYPLET5yD453j22oKEKtuZxS+89D7nEzvAUzrUX8
         j3gg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUvppgUvEVUn/qRWQu+2hs7W7Yv5ETK8WLZtzeFnFxMvABt8sE8
	ojDtUMsxGQvm9jdRW0IQm84=
X-Google-Smtp-Source: APXvYqyqhSR5ElL2ngNvMALVj0fxyK/KcsghCJUOcT36xv5XaS3+9lX6VgKNHla+RPVq5qhrwVfJdA==
X-Received: by 2002:a63:7e09:: with SMTP id z9mr679830pgc.383.1582829373390;
        Thu, 27 Feb 2020 10:49:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8d97:: with SMTP id v23ls24736plo.5.gmail; Thu, 27
 Feb 2020 10:49:33 -0800 (PST)
X-Received: by 2002:a17:902:8213:: with SMTP id x19mr141533pln.161.1582829372930;
        Thu, 27 Feb 2020 10:49:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582829372; cv=none;
        d=google.com; s=arc-20160816;
        b=rKm9wllUz5x4+IYzq801NL8DmLR8cuzeJhIjFECwKbhsdWYRYwE2ChzYaF006ezKAJ
         b4k12CHBEVrgUrd1+kZl0u26X2LNcAVuA26Xt5PHmYAmjxwc+MQUbCMlkz3dZ5KQ+GcY
         Xhhejh0btkEWxpgHp75TwQ90at2W4dyfDKybea+xwdbpP+00YW2e/rffe8fyNtsDwtj1
         jgv0r/dP+lan1pSi9kBYAci1iHS8k8AW9y1jhR0qIwlRIoXxUBoJtjS99REvDWcY9YYy
         ZlcbJUcA+L3+44r59PxIZQ8BMouelWKrS5oqdeC+ONwSITD104ybST80+E8NTGumW8su
         EDBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sVbVapbdvm9D9bZT8RLizJdch6+5SIEY/KYRYQVG8Tk=;
        b=xZiDrH219PnQ0msAFkOYBtaF+JzgLl2F50IxLMSm9BrtpT788adtROhxG+8XFd6sX0
         IUMlgAJYGsEFyeKisWLtImbvgbBHZK8U/AJwBjQ3/AB7XS0g+1G8cGcrk5vrJvcS2+WJ
         1ok9b1XtJU0KWTMPw+LS3ZYiqF4SeBgEQlZrA4SbbX5GVYGmXkp5pMRqy4T2Ad+QMOAm
         IcBSyeacQkyMLnd/1Zzlte6UvRrDCx/NKrVq8waF8CaiErs4p5LsqOWyjJR1b8Uubn92
         ykSNiPrw9Lo60v20b3traN36TbQANjrHhxW1Qj5ix1zPkKMq66prbYaBKJWhCXK2qBpr
         MP7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=X5i1lW7g;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id h2si325657pju.2.2020.02.27.10.49.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Feb 2020 10:49:32 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id m13so173008pjb.2
        for <kasan-dev@googlegroups.com>; Thu, 27 Feb 2020 10:49:32 -0800 (PST)
X-Received: by 2002:a17:90b:8d1:: with SMTP id ds17mr352661pjb.33.1582829372673;
        Thu, 27 Feb 2020 10:49:32 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id d22sm7629675pfo.187.2020.02.27.10.49.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Feb 2020 10:49:31 -0800 (PST)
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
Subject: [PATCH v4 5/6] kasan: Unset panic_on_warn before calling panic()
Date: Thu, 27 Feb 2020 10:49:20 -0800
Message-Id: <20200227184921.30215-6-keescook@chromium.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200227184921.30215-1-keescook@chromium.org>
References: <20200227184921.30215-1-keescook@chromium.org>
MIME-Version: 1.0
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=X5i1lW7g;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200227184921.30215-6-keescook%40chromium.org.
