Return-Path: <kasan-dev+bncBC6OLHHDVUOBBXUXRSDAMGQECN7NBPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 44B153A3CA0
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 09:08:16 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id p7-20020a5d8d070000b02904c0978ed194sf7206447ioj.10
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 00:08:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623395295; cv=pass;
        d=google.com; s=arc-20160816;
        b=Iy/e8m7Er7MSc+O718XxSafQ0/8Q76BB/65ped6IEDTGgdCJzQ4wZrDw5M1EBowfLl
         GrhESlavq5ROTQ8kJslO8RHvroxfNQQJJHngEdMi1Ei0X7qG5f3rKcmzkn3uDvc02yzH
         0bvpSdTESNieA7tynKQKsOSbBDvzzlZmfUHo2/uE1ZLfcZ2zdz2jiv2+NKdFQ5SF1R0q
         WVHX8vWh0RjDdT/gPVhJT0ib+zoRmlbcyUc4DiiMjOWbIJPgbTmKI+zLsdcC7zmbLiop
         ETu3SiXifZKV0bINsZrh9/J+S9YA2HclNjITxr7tLJvQsG4iJoUbfHh0J852EPfeHuPd
         Lc7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=GRvuuVM0cvUBMd955xyzMRoYsdg+WgJUJnvtlxuFkQA=;
        b=L8OMa3SEe5MYl603ncYKOe6/goagptLvMl1kkhsXCFV3SoyBuNwcAYNb0Kbnzly88J
         d6eLo1x7dFOEAL4DKnwhMMwxiunBxmElmCdpgViLSmV/eq5V4kSdX8aV2D71waSLWM1y
         FXfGGllMpQ2CY4RgmYBYLVBZOLSbIt7+zLnwaTShlp+xtfhf1AyOnclfB5GKupSaXXje
         Si+DdzdC5sr4VhtbB13IY56Ltg211WWkjDycFca/3Pf0GEPOo+Qj+U9RtxhUXVk4iFCo
         V3pJGjNTVinrLA75H1beIzxH9I4ytkJdVCW3b+WfVt2r4sR3Si2QPPWpkT1HCGvDze39
         69qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j+989NVx;
       spf=pass (google.com: domain of 33qvdyagkcq4ro9wru2au22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=33QvDYAgKCQ4ro9wru2Au22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GRvuuVM0cvUBMd955xyzMRoYsdg+WgJUJnvtlxuFkQA=;
        b=o6XzmwmpAiXaJ70Nk4O9V+hQCPJQ30IyaIKrTjjbLzTAQrQpWjgf+YQ4G5/OsQ3A0E
         ol7VTmSccc1lreRVxl3WtObTE3JKUKFmfeJUenKhVi1R9Eq5Grwd+9aGwQcPTZGWzQkE
         qp2BOs3mrnN7ZvIJKgzydlNZldutg1ykBEOWS5T3GYn3lQvjbwrMOnYb+QkYBrpaSE4Y
         xpZP6rpm8eocZIhAw01e7YqZ4zstAQuQeyCMOQenEmQFpcsLxh6ZI4NB/Kf75dXaOgBr
         0WJ0DHW+HPbGpvdZj+JDCGUil3qD9e7M3CwJEVf8FRV8vWKJgP2Bx7g8RGOuAixIn2go
         BG6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GRvuuVM0cvUBMd955xyzMRoYsdg+WgJUJnvtlxuFkQA=;
        b=JqQVyBH/0vVCFfg/q0asOF1PPdUY6TIVhVlXaI9zahbjksesA77LXe9RpsgIQcTYjm
         V0JYqTlwMITofxyV+MhJjfhzmRxFjh+teOZgJDa9Yr0XuO5wl5/AN3dCJ6p5nPP1mrxA
         qMNyit5kHRfUYAvP/92cky8vy0U80sPPc5moIna//ZA7Eob9JNZV70c5nBgxT+0ww9GF
         P1u0yi15w+lBrCuR2IYkCiGvsJqhjhtRnZ5Fovpt+qIOyYGGOrbqD9ZaDdGSggEAxtYd
         vt4aq3ADauJgxckwpoVV9nDWMZXOGj1Ds43uYz5+8yA+kWTSk+9i+1GBvR7P89mT+e3L
         WeWw==
X-Gm-Message-State: AOAM531yIyNH+PVRGJd5BxvBb4iRjmkGWf0W6gHjCLatU13JlK5yFZ13
	etAXEPMmkibO16C4wzPNY2g=
X-Google-Smtp-Source: ABdhPJzLQFmFFYPV+h48WnYHiAexPJUXMVgnxw0v3ko2/PFT75gFjHPXY2Jp03zv/gjNl/dSue+FAg==
X-Received: by 2002:a92:c003:: with SMTP id q3mr2182889ild.128.1623395294918;
        Fri, 11 Jun 2021 00:08:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:8d50:: with SMTP id p77ls1575876iod.4.gmail; Fri, 11 Jun
 2021 00:08:14 -0700 (PDT)
X-Received: by 2002:a05:6602:2215:: with SMTP id n21mr2099954ion.80.1623395294465;
        Fri, 11 Jun 2021 00:08:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623395294; cv=none;
        d=google.com; s=arc-20160816;
        b=Nribqs/yrJYni4wpX0ggM/1h76fQNO2+/pwOS6+eTt6X5dWyfV9L666ZIzJIyq33kS
         yrm7PpEZRcW7QudTB6Go0s7En3IKzGaHsnF0FCeqd2Nq0BMUdfb+wDQVWkN0YvEw0WgF
         SlPc9RuHQxo2cncOYCjzV6ePHDWnE7k6T6cVeTGsLoK0e7LUH9Y+rCKjIafwpQzuIsWC
         7T+fX9EH+mJ3QTFdvH7WTr/JG92FJkS5Vm/Gb8sZrAHI3MzG80ktdGC2hWOUpp/c+9iL
         OpdYa3moG0kC4JmSgx7pr2SpBrassaxNSgqb9u+ASyyLwGkkc+6jvimP1e91oozgDFSL
         JFpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=LQ+bL0LyWEuBvKFw9/83tjsdx33/GmsNwb90dPirq54=;
        b=tWQzeueusnhEtIUTNfsCFu3ssEoLnnDp+0Cti7JlE9hRN5K7ylU8fuXksqxWtOuov3
         87MY+m4P5pkVLaJdUyb2lT3Eq/Wjtp3f8Cxt1ezimcJ2e5nR/uHAILhdFIjas4rJ4SSQ
         63NtKfLiJcJTF7ElgvIO/2+fNy9CrIgtGdoadNJ8/7Kzl+Nb8a8Zp5alcvIjN1MuMTxw
         QeaBL/dUYUYeFzOqsbcf+ZnUUoZ+bqMBpiaS+rFQaBLDfaIBCV3a/5Bi7oOHETKMDO2d
         k01B+DVM0afexoo8pD/CQpixnKmA1aakyVE002NzOPGBHYGjLvkVIlqLzT9B301U5Gdk
         vesQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j+989NVx;
       spf=pass (google.com: domain of 33qvdyagkcq4ro9wru2au22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=33QvDYAgKCQ4ro9wru2Au22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id q196si457314iod.3.2021.06.11.00.08.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Jun 2021 00:08:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 33qvdyagkcq4ro9wru2au22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id s8-20020a5b04480000b029049fb35700b9so3011921ybp.5
        for <kasan-dev@googlegroups.com>; Fri, 11 Jun 2021 00:08:14 -0700 (PDT)
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:b697:a576:a25f:5b1e])
 (user=davidgow job=sendgmr) by 2002:a25:218b:: with SMTP id
 h133mr3766811ybh.160.1623395293932; Fri, 11 Jun 2021 00:08:13 -0700 (PDT)
Date: Fri, 11 Jun 2021 00:08:02 -0700
In-Reply-To: <20210611070802.1318911-1-davidgow@google.com>
Message-Id: <20210611070802.1318911-4-davidgow@google.com>
Mime-Version: 1.0
References: <20210611070802.1318911-1-davidgow@google.com>
X-Mailer: git-send-email 2.32.0.272.g935e593368-goog
Subject: [PATCH v4 4/4] kasan: test: make use of kunit_skip()
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Brendan Higgins <brendanhiggins@google.com>, Alan Maguire <alan.maguire@oracle.com>
Cc: Marco Elver <elver@google.com>, Daniel Latypov <dlatypov@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, David Gow <davidgow@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=j+989NVx;       spf=pass
 (google.com: domain of 33qvdyagkcq4ro9wru2au22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=33QvDYAgKCQ4ro9wru2Au22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

From: Marco Elver <elver@google.com>

Make use of the recently added kunit_skip() to skip tests, as it permits
TAP parsers to recognize if a test was deliberately skipped.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: David Gow <davidgow@google.com>
Reviewed-by: Daniel Latypov <dlatypov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
---

No changes since v3:
https://lore.kernel.org/linux-kselftest/20210608065128.610640-1-davidgow@google.com/

No changes since v2:
https://lore.kernel.org/linux-kselftest/20210528075932.347154-4-davidgow@google.com

 lib/test_kasan.c | 12 ++++--------
 1 file changed, 4 insertions(+), 8 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index cacbbbdef768..0a2029d14c91 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -111,17 +111,13 @@ static void kasan_test_exit(struct kunit *test)
 } while (0)
 
 #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {			\
-	if (!IS_ENABLED(config)) {					\
-		kunit_info((test), "skipping, " #config " required");	\
-		return;							\
-	}								\
+	if (!IS_ENABLED(config))					\
+		kunit_skip((test), "Test requires " #config "=y");	\
 } while (0)
 
 #define KASAN_TEST_NEEDS_CONFIG_OFF(test, config) do {			\
-	if (IS_ENABLED(config)) {					\
-		kunit_info((test), "skipping, " #config " enabled");	\
-		return;							\
-	}								\
+	if (IS_ENABLED(config))						\
+		kunit_skip((test), "Test requires " #config "=n");	\
 } while (0)
 
 static void kmalloc_oob_right(struct kunit *test)
-- 
2.32.0.272.g935e593368-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210611070802.1318911-4-davidgow%40google.com.
