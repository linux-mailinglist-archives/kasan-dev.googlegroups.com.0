Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQUCT73QKGQEL63SUNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id E33D51F9F96
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 20:43:15 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id o21sf8460298ooo.19
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 11:43:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592246595; cv=pass;
        d=google.com; s=arc-20160816;
        b=SejjXt/f/6VCWmngLSC12QQnchtizq+xA7nNHvSTQnsUYSE3QQQjH3ZCRYu4OQEXXC
         uDhT7pgpttVuvetWg9XC8WwWzyBXY3CVtoLCmv/LnxAUsg9tq7gOyDwx4CPqFH6n0GjD
         E/h5KpCSMeJurCH/GV1BctcHsg3kkxO3x3MxHmuusUS30nkkRnXK/M1ex+E17eEkcFei
         8fSX3UBVS/bsm1ZKpk5tcATzpdAoDVeZrL7QKVAYeA3ZthEso5yMfVS/VOAWJA05hXHB
         05d4z2JKMvG8U//VRKRXx6PE5ebZiovsAfAyWiknx0u2YjOew3EZZDnBBsvPmSVmpErS
         qyzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=KqvsiTbWBob5NEOZ114bV4k9NH+YF2MrTIxU/RJGujE=;
        b=KtrsuWmJAPmDpbHIzKNaKgMjnvMQIyoXWXlyYq4qce/Ulkci66a6NA5scx0r+26CIM
         GHidyqUlI1MI4U7sv3J0fWsAB37T94m5TerPagT4+bvsMXh/6jc8XnMJjJ3WUH0w6HvS
         8qSCg8MpeHQO8fvQYCId0mmVawvmtueM/HI1cDuGbFE54CVTnxsVtYARFaCe/H1ndWMv
         LtlJyM1ZWTWI/A+8237hevczW3P1QXWbbbSdbN4oX8NuYwtwY5UhyCvyfe6rVh+FK4MR
         8afHV1FMhI7lCnxJ4WIwsP+eIysXTzDsBRs+69c8uyPkF9IsMqxSx+YC8pnflUzK/EKN
         OqVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WhWZYW2C;
       spf=pass (google.com: domain of 3qshnxgukcwedkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3QsHnXgUKCWEDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=KqvsiTbWBob5NEOZ114bV4k9NH+YF2MrTIxU/RJGujE=;
        b=mHZBhu9UHyoSTktZYqDdN+AwRCXCBLSmpwCHyNPEM7Z092NWWIef77adH/b2pXukQR
         ECZxfdmWJrOTC2af4BbPOFw4tuEcjdZ5RDvmusWhJrln0nR6dqyntJ9eOeEU/YW/dnTe
         FcZCahK0kQOXrmVshaxRVZEPOfHN2r5ywA6UrO22IDf9QKMRSZqNoe20t5AWYHLM+bx6
         /xvUsZ8cEONAxc/zhFYO6KLmCmGjVwk420c27kNiuUNaBb5zDZVg4oVVOl8IyJO0ny+r
         Cabt+f/0eQhuYkFnWZkbj0EPCcegmKsLIu3eVX7YdT+FEIfTZfrZZjk4NpvZhspBQPJk
         9ZaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KqvsiTbWBob5NEOZ114bV4k9NH+YF2MrTIxU/RJGujE=;
        b=PGfawiBI6Iuimrxa80D7wW2Lcl+oB6MkjV0bqYdLO2yOiR1YzGRVuineoVUJt4KeF5
         FNag75Y3DqVtiqKJjUO2oPSFCqETynZcddh9Q+kVoJiEPwzkTMrnarAOQgA3XeGHyJAt
         AhIVGVhMVb9aXlayegbVGi09JZpY6GTm4cq00YL/5f41+nda65En1To8vyeSzCORzLQu
         XwvcjJ+CvyLkanrxxoSBSxyGZgEct7scv6Bd4Jro6uXEzsZMFej5L7F1WfaIIQm63nYw
         LOZDpe6Z5XEqQ9JF6MWK6+g+2QFJTQPRxe1FltReDaUTXBHOmq6lh0i4tOschlK3P9N1
         fHLQ==
X-Gm-Message-State: AOAM531cVf86PmI8J6CZ8gDshWZN1yivyx7dS+zB/Z+eWcsKu2G0oDpg
	mDe8qittnhyGX1+Kt1Aoe2c=
X-Google-Smtp-Source: ABdhPJwA9t/Rnt0vSl5DlMt1NVIUPFiG4d4RmWq1KuDJZruAHjup/9Y1yBXiP4xkIxnPp9oQyVcxwA==
X-Received: by 2002:a05:6830:2004:: with SMTP id e4mr22798687otp.85.1592246594925;
        Mon, 15 Jun 2020 11:43:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:16b:: with SMTP id k11ls820477ood.4.gmail; Mon, 15
 Jun 2020 11:43:14 -0700 (PDT)
X-Received: by 2002:a4a:e049:: with SMTP id v9mr22243546oos.22.1592246594603;
        Mon, 15 Jun 2020 11:43:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592246594; cv=none;
        d=google.com; s=arc-20160816;
        b=VDqSZaI8260jdHqRBEd7RXN/E6amzr85o6/eS5QtZrRppargSvDlwERPdV/9xjhR6O
         d8th79u9LbSexjv8gzwjIBqiGiA4xFn/KltlDpxDCjufkyDumWjSwKgwZ4mIDcq4tslI
         mlrz3z1+3MXn15PwdokxFcl9+OjnqO9WLy9zTIp/2VmCe0grWOZTlQjpS3edmQjLnvCX
         whX4rJO2kfMEa0/jlQvqFNWUpHL6vpt87TGRmbvtC5dGBBTuoeD2/ppYBW34BjAIOl/w
         SFzk//nRz3E2fk7Y9D+V+XvCob1f/25NtavqzmK5nQUhB6sw912yZGlZJNGXVevRh7XM
         NCfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=E5J9eW43iWDhM6NCP/M18PRrar5zm+KpAYsU8FhxzQc=;
        b=EcC5TDR8hfUSLtAnl6XOEHNdLPP6NQ8dXPXtN4ZynUBIzsZmZjmYZGGqm8e6C2+vEN
         zQycwgQdzUAXSy9m8doqnJ7yGHtaVELjscdlqpQRv2f1bb2oKF2MtlU/idAaGJjWng7B
         ZIee9y6sVlOkV6Irl2PjQf0QsHJiF2kVJSr/NkZIA5VSqvqPzzW+wrk46RbZThPzaSO+
         0CWNSkDgoCWbv1edjJV+38PD83K4ohCpSktTJDHEOLn3IjMvyqDzft0P6wuN+X0/szTJ
         I+dTkofSwIYr5wOenidsaZZ878XahOPDgyz/f/u0BArUNrc4KQvP4xPKzSMCz3mI2hJG
         ANvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WhWZYW2C;
       spf=pass (google.com: domain of 3qshnxgukcwedkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3QsHnXgUKCWEDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id l9si717180oig.0.2020.06.15.11.43.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jun 2020 11:43:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qshnxgukcwedkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id f130so21744701yba.9
        for <kasan-dev@googlegroups.com>; Mon, 15 Jun 2020 11:43:14 -0700 (PDT)
X-Received: by 2002:a25:50cc:: with SMTP id e195mr48552837ybb.483.1592246594106;
 Mon, 15 Jun 2020 11:43:14 -0700 (PDT)
Date: Mon, 15 Jun 2020 20:43:02 +0200
Message-Id: <20200615184302.7591-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.290.gba653c62da-goog
Subject: [PATCH] kcov: Unconditionally add -fno-stack-protector to compiler options
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Nick Desaulniers <ndesaulniers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WhWZYW2C;       spf=pass
 (google.com: domain of 3qshnxgukcwedkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3QsHnXgUKCWEDKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
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

Unconditionally add -fno-stack-protector to KCOV's compiler options, as
all supported compilers support the option. This saves a compiler
invocation to determine if the option is supported.

Because Clang does not support -fno-conserve-stack, and
-fno-stack-protector was wrapped in the same cc-option, we were missing
-fno-stack-protector with Clang. Unconditionally adding this option
fixes this for Clang.

Suggested-by: Nick Desaulniers <ndesaulniers@google.com>
Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
Split out from series:
	https://lkml.kernel.org/r/20200605082839.226418-2-elver@google.com
as there is no dependency on the preceding patch (which will be dropped).
---
 kernel/Makefile | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/Makefile b/kernel/Makefile
index f3218bc5ec69..592cb549dcb8 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -35,7 +35,7 @@ KCOV_INSTRUMENT_stacktrace.o := n
 KCOV_INSTRUMENT_kcov.o := n
 KASAN_SANITIZE_kcov.o := n
 KCSAN_SANITIZE_kcov.o := n
-CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
+CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
 
 # cond_syscall is currently not LTO compatible
 CFLAGS_sys_ni.o = $(DISABLE_LTO)
-- 
2.27.0.290.gba653c62da-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615184302.7591-1-elver%40google.com.
