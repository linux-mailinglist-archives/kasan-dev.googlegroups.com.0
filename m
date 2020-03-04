Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSVN77ZAKGQEKCQKJUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AE0017950E
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Mar 2020 17:26:51 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id w12sf751798wmc.3
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 08:26:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583339210; cv=pass;
        d=google.com; s=arc-20160816;
        b=j4OWREgHfPDDwBZ9NTs1RLctjp+d0uO+5O0WGKkaevTf05Z7dlsaV1BnKWhclXP8WM
         +pB5rT8zDNiCs9stx2tAMpooASp+e/2pG9OGfCMmYDzgBommocUFlVniski1VRCCIg56
         pkSX+mqB8rLJOW7Iu6z0JVeEleU/oLQQG8PDlVlRcD1esrsBq8r0FWS5hxctJgTBqi+u
         2O+4VKxOoKCR4MXVhPhBECAvPU0xnMh3GEDihkoy0J/j3ytAeV4+37Dps8TmHlZgrDJ0
         bAg4VR5uw2BppDfMwdogJNyYoRa5Xf5YvOHYSHah8/sPNDyU3a44WECtY60ehmcZoagG
         7Mhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=SVUcfh7Py5kZ5W37fph2eGzLZ4oG+fCQAjqZujASJ4s=;
        b=Ji+259pu9Mge/fRRVtkLRc2eQPnRehMTmjmgYv+yPIi1V/woU7c6dV6OFb3ViF6RwZ
         Ten8eFiSQDoYWIiu9NcQD1PXIqeHMjSeJSE5d9yYqCbYmLI15kXn/Ka/qYoANmxTbiPx
         HL73md8l0AOQWZxyzDiaQ7L0UmG2fYLo2qMHvmBTpSMCMAg0GpMphFehtF0vEHQx5KD5
         EmWYZ8In3M/D9/OaFQYuTqwWKVqI4PoJORTLmTrbE8r7X2na1R+ZIrNiR2ktcIh3BA0y
         g2ufZtrV9+shFPVeigqjw6hOuI5+AkkofjE3KLWEO1/3BItiNdiFk8lXVZfTYhHEi/yR
         1K2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="qZMF/8H3";
       spf=pass (google.com: domain of 3ydzfxgukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ydZfXgUKCe4UblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=SVUcfh7Py5kZ5W37fph2eGzLZ4oG+fCQAjqZujASJ4s=;
        b=CzwFyLFI7w1SuhVHVW8w4o45aQCIAHWhCFHGhopUFE2rYvRbuw3DHk4KckKsIsywK7
         ghN6AmBDCO2qnYqspiV+G3gk/Cgx4ptfJRY2O0EgHftYApPnG6tagoSaciZxRl9kTL9b
         y+H18DWUf6m78CQo0WaPTiESvtnYITzMOQ164YWeWYa7J038m0JDWtDENO36PNJjC4a3
         eD4DYUJ0EamiFAWfqZ4x1BoYOTwbAC/Aw4TSMq63VaX/+dqXE9E6nbjdW9RSCrjhQA0r
         BjiqO59NcAIhdYzlABwRk0d390MXTKHBnKBBxbqH0qXrcELFxPiYuJ1UIkETCB4ta8oq
         +D4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SVUcfh7Py5kZ5W37fph2eGzLZ4oG+fCQAjqZujASJ4s=;
        b=ei8+Pq8x5DmExKBmGlPMB3KfGoXPx9dJLhQMo14q0gov98jfxLDrqyw15vGhuCOkOH
         DEwnpAgdL4mXuw25wbZGXG0//uM1KrJHC/qCIC7YtUUVyM1iDi2Qpt/znK89JBJDKL3f
         8Os8PwRYw7dKexs8/7ZZ9D3tZOr022OFXl9mDbkY/atp3rZ+NpsIbt3Sb/47fr+waZf5
         PIQL+TjC8D8739jiLH46waX6UfC7bci6scX4HcbRNoXgkFkyC8iufTJcE5FX3Met8phP
         e7sy2OhvY8R62fA1xgHN72hS0DdLKD6ELNAHIaRxFSm3uX/QaCaN2++gHAz6nEmn14Sq
         4Ghw==
X-Gm-Message-State: ANhLgQ38BMnKE084vflgwnqNTCgOcsr6qkenlZThnz+OjKxTeRZb19e5
	wuMCoDIPOq4FhHjsoU7mFh0=
X-Google-Smtp-Source: ADFU+vuueUDFVCtT0oFXc4I0bs64Qk7viFKDHZkvvntJetJPCjfmkmwImz0lG+oCdX8RC0hXAUUqGw==
X-Received: by 2002:a5d:638b:: with SMTP id p11mr4937103wru.338.1583339210775;
        Wed, 04 Mar 2020 08:26:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:dd81:: with SMTP id x1ls1342677wrl.1.gmail; Wed, 04 Mar
 2020 08:26:50 -0800 (PST)
X-Received: by 2002:adf:fd92:: with SMTP id d18mr5064377wrr.16.1583339210112;
        Wed, 04 Mar 2020 08:26:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583339210; cv=none;
        d=google.com; s=arc-20160816;
        b=znpWDyHpdGLUakzm2bLQit0FR6Gy/MawSgaK3TvjXBUWYMfHKZZVgWtCYWsMfwEyzP
         mJND0H++/7V1OnXmbXKPsaFOdASAbrcZmJtsIsLyVuY8CA37ODX8UGw50itC62PgSo+M
         vFtCXrkeRznYRnccpF0++MK99vSDlbN9pQ64iR0+Mw0yZ/TAgpOLsCshx6ChwbKVZisg
         ZTyLrgiQJz805HyxlSNTt9jNhRgSXiotp65l6m8ziH42bU7gRlmgneMXT1q590ixM6hU
         /E9urMyNA7PCOCcB+ZrJ7gjJzZ02HyCr60Y9aUqwfMBQJsJwp4hikd+W2FSmGVV0zOJn
         3/VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=KkLXOOSG3EccFvXnveAsAjlCd4Cuj/e0jkzvyAbgB9g=;
        b=bJb5n6+VaoGI/cYXfpW6lVxHfRoeDhpoPM1bALQTo9KY7NpbYyPBkISIAb39YsMYHu
         xR3bGXDAg5/lLs72JZBgUDg9AvNZqkYfgl7FxnQMu0a0sY1Mrux5iDjWCRJh5uI+c7J/
         EvIRTz2SslIpj94DZwRFMz/Eh+PiCUojBNvVMHiz5ScWUeFqDSqasUMpQAlXHnvPgNCw
         G4bN6tObEIEi1sRsgUR/o3oMeeGmzkte/3cgnAXInzivg1wEghYqP5mXR9BLvucSoIY7
         7uNpi65d0HjeNhPERBqD2traKTMZ0tTjNEO50YyZS3ta5BlTvBw/+HQcaED4r+kCjVBZ
         0Jng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="qZMF/8H3";
       spf=pass (google.com: domain of 3ydzfxgukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ydZfXgUKCe4UblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id l13si130792wrp.2.2020.03.04.08.26.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Mar 2020 08:26:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ydzfxgukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id m4so1056448wmi.5
        for <kasan-dev@googlegroups.com>; Wed, 04 Mar 2020 08:26:50 -0800 (PST)
X-Received: by 2002:adf:f4c9:: with SMTP id h9mr4909942wrp.168.1583339209473;
 Wed, 04 Mar 2020 08:26:49 -0800 (PST)
Date: Wed,  4 Mar 2020 17:25:39 +0100
Message-Id: <20200304162541.46663-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH 1/3] kcsan: Fix a typo in a comment
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	corbet@lwn.net, linux-doc@vger.kernel.org, Qiujun Huang <hqjagain@gmail.com>, 
	Nick Desaulniers <ndesaulniers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="qZMF/8H3";       spf=pass
 (google.com: domain of 3ydzfxgukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3ydZfXgUKCe4UblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

From: Qiujun Huang <hqjagain@gmail.com>

s/slots slots/slots/

Signed-off-by: Qiujun Huang <hqjagain@gmail.com>
Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
[elver: commit message]
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index eb30ecdc8c009..ee8200835b607 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -45,7 +45,7 @@ static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
 };
 
 /*
- * Helper macros to index into adjacent slots slots, starting from address slot
+ * Helper macros to index into adjacent slots, starting from address slot
  * itself, followed by the right and left slots.
  *
  * The purpose is 2-fold:
-- 
2.25.0.265.gbab2e86ba0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200304162541.46663-1-elver%40google.com.
