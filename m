Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZUVQTZQKGQE4PZ3OQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id A68DE17A744
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 15:21:26 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id k65sf1634551wmf.7
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 06:21:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583418086; cv=pass;
        d=google.com; s=arc-20160816;
        b=JHsvZGQ6g2bdKaL6RHyuAnZrlsbzB8SWypKA48J1cCLkXxLYZCRdLDnNXHRgNBpuHa
         c3h9o2SSdDvzWIDQ7nJJ76NAjGpwapXY0kJYBgE4Z0IEkbCjb+HfcMW7KSsoaCu26Npn
         KXi/eEkVDUH6GP/d0Cu1iHq+r9FBuvbA4S6ShoWLwsPGGin2ilIE9/r1yoS8eruVVL8p
         hyYnkuZgUuYnrNt9LPb0eRo4RCeLsKfbTKsL5MDDMlBGMLI+tn6LiU89Pc02MZB5UcrJ
         +RHin323L3rmebx2gq9flbqH5G/AyYdUxqtVQ+GjkZS3G3A5GtzAWELd3BgR9HlHd6P/
         G2Fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=3KA1KZo1TP1uHyChy9Q2XdgpKHzcz3lTDoWNlTb4Z34=;
        b=Yrog0VmFudtAV5jBe89vi11z0+Abs7yLIWFvY+glPBEswE2J3OSs6+YP2Zm9SLi7Dq
         lLXf3rPYeV0kW2N8DzpzTZ8p8mm81YKCVejAQt2TsxDItGXLZr1Ti5Cxtawm2IiZG7bZ
         42diZ32q+Rs4eUFyJbZr6hH9szxf6D7dEpr8INmiNR09i6wfKI/oM5OdSULe1UG4fD2m
         q+DhOYyLKHsYbVEPj1gP4urH9h5SXpjvgo9vql5G8w3HQpugrr8Vt8d2sYDayE3WE6f6
         1G7r0RwJ0Pr9f1rr1TmtH3ir3mfr58wCcd5Bqw8GFpNqcE2rt3oDgfTNt5UnM5teQ4h3
         5CWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JAEu655o;
       spf=pass (google.com: domain of 33wphxgukcxiubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=33wphXgUKCXIUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=3KA1KZo1TP1uHyChy9Q2XdgpKHzcz3lTDoWNlTb4Z34=;
        b=WitA6brVabhXlzGcDf9Q0/cvFORN58f+Gx7uHS4vaPZDG5BmbV9d4Q0WV9js14NjnP
         WG2jCIMOhYw9vnKsZ9SYWlhW4CzHT5ayKwQS1l0PZjNbjJ+EG430LZHJ8lQuT4StURw2
         e5ExShaY7/k0cAVHyFKactnucxh+W9jrySxXN0YCXue94YveYws8dFd1bDHEPXNCmCkP
         8HIwtcYVqYbiyiDopodXTIycYVqlf1HWyWXfJhmEfVmxq3CCCxwiXecv8KOVvBmA4QgF
         UNQ5A2W6DZg7ONQcuAcQc2Rh9ECdn9uDmEaKz6WUWmqmFxmcWAKfQvBH9o7U+C8tP4za
         Gp/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3KA1KZo1TP1uHyChy9Q2XdgpKHzcz3lTDoWNlTb4Z34=;
        b=hUPIABKYjGtFz8pZf0p2OnKt2/y6hm+1BLtr2z+B0YoVC+vlqjPnaPNiOpkM8pcwVA
         JHjKyaKbtjBTwfssJ+3TEUzomediV3wtVERzJnn3l0ysHPq6cvRY7BhWt3tofqfUuO30
         VBj1Vb11F2OmZkpm3YSIwr5NKQFIWYZT+hgwNImG+srsmXS/z8gW2AbRF2DEMvrliVWg
         7AxamUXiqS5m221pSgKy3mqIQl/MK0mYJywRqi749pRjlI4hJpFIpUvSqszj/Fd75+l2
         DGN2Kx2BukM5ETH51D+sdvx1rUsRMsDCWYU4mlp3fe4rcWmz4tOlmGCuM0Dwc3LBdFYw
         rJiA==
X-Gm-Message-State: ANhLgQ1lcYpC5Q5XnKNblIz/DM9YiNYs6NY41xM7YdyHs1jPhMbenBZ/
	Hg0WAbAWmGKMNhTVgTZHgb8=
X-Google-Smtp-Source: ADFU+vs+3hJZYGKBhuOM/8RQimzg24V3a3LE1gzLvnFOnf6Y1H97s+gU/E3USBbPoMQQ6eLV9oI/kw==
X-Received: by 2002:a1c:7ed0:: with SMTP id z199mr10483855wmc.52.1583418086432;
        Thu, 05 Mar 2020 06:21:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:508e:: with SMTP id a14ls580093wrt.2.gmail; Thu, 05 Mar
 2020 06:21:25 -0800 (PST)
X-Received: by 2002:adf:fc82:: with SMTP id g2mr5181278wrr.117.1583418085656;
        Thu, 05 Mar 2020 06:21:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583418085; cv=none;
        d=google.com; s=arc-20160816;
        b=HGIfExb1Z6CYfrWBTjSIdq4TVCU4esgn7ZW/K93bS5Ji6zaf6nn9cAUe1Lu0ey2Rbm
         8w4Y6FTxJDw0ouoyYAGW6XyOXrCoSR0SdKiIXuOsmqdQwLXwZEqrq84k2e5dBOVg7qcz
         9iysrwGXy2dcasxm6rEEJrGylssj0iJvMmIMmMBMkQ+QubyJwDtMbhEzDwYnOywnKgIu
         Ebb7uQgTqP1b2z/uZ8KSkD7387NbfPtPlFp5ycc+PRnDmGHWw8IhlNbg4kd48uUqclYa
         OsXxTY3V6tUSQ4QzBJKRX9RbgGafK3ZWpC5nRyBWfl30YamymakgRen/pl98qAhwsv04
         Te1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=KkLXOOSG3EccFvXnveAsAjlCd4Cuj/e0jkzvyAbgB9g=;
        b=r755oUn+Iw+BN2lAbd9QHSwK1zawosv6ueW7K67OtxYQ9J6BvdlZVy/wBjlz6HMKWM
         xKOZf9xhYHGO2HxQnzOkJKv317rbTCuAUbvvS+DBaLYygpamiJPpTApg0FlKRqpz03Yi
         q00BQ38qJPtSG5Yb4PBKWBYAh7H2wInTQqYCm7nQ8eZihlKuw/l531SJ8fNYUXzUvTMw
         HSyRUZ6+JI4b6oxf2+NN3UoQi/bgHRQPRgV8h44vTYTW8KUZHa+5vGvs62lUuIP8Pd5X
         UlvP4YMsDL3EVklMz0Tjdt1i+X90/48eSqbm+Mh94+MHcRASngwynvXw4h3ucukY5lVa
         SDVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JAEu655o;
       spf=pass (google.com: domain of 33wphxgukcxiubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=33wphXgUKCXIUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id d14si265704wru.1.2020.03.05.06.21.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2020 06:21:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 33wphxgukcxiubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id m4so2144741wmi.5
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2020 06:21:25 -0800 (PST)
X-Received: by 2002:adf:e742:: with SMTP id c2mr10459658wrn.262.1583418079894;
 Thu, 05 Mar 2020 06:21:19 -0800 (PST)
Date: Thu,  5 Mar 2020 15:21:07 +0100
Message-Id: <20200305142109.50945-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH v2 1/3] kcsan: Fix a typo in a comment
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	corbet@lwn.net, linux-doc@vger.kernel.org, Qiujun Huang <hqjagain@gmail.com>, 
	Nick Desaulniers <ndesaulniers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JAEu655o;       spf=pass
 (google.com: domain of 33wphxgukcxiubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=33wphXgUKCXIUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200305142109.50945-1-elver%40google.com.
