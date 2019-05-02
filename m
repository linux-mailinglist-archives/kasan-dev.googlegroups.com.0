Return-Path: <kasan-dev+bncBD4NDKWHQYDRB3FWVTTAKGQEPU4IHDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B0331203A
	for <lists+kasan-dev@lfdr.de>; Thu,  2 May 2019 18:31:41 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id m3sf485864lji.10
        for <lists+kasan-dev@lfdr.de>; Thu, 02 May 2019 09:31:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556814700; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZZvP/XFBwnfIYG3XEUIgzkhhCR8ag2fV43BFfca9EAFJhK9Bg8BKbwggG2zG+KrTm3
         ro719l38t/7sRgO79X3DlU0fvMudTgT0TbZ0bWCjqjX9vXTI21auzF/cOH6iD7USTLw1
         40sj2SWSdNQwX9vY/tWVzzrygN+NpfLZ3dXwySl3OAYAofXRiULHAezEjlv7WG1afe7x
         jWQQhB7HbWbfkSnl2y9CwGX4+6jluufLiebrdXkQuHvSmt73zdyPeodeMDVC+EKsKIPH
         606h0KxOSoahPYzvt5bSGSDyY0nJX+QSmloe89dhTmB50IUUpMGSXBfQpAcrHZlBZtbS
         Hsyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Aj2u/VB95LIn99gkVno+FJnexBCaY9AFf7KOoF/mav4=;
        b=Ku7V8nalXYjDNCEVRfyBu+wp9Kw1QK+WWnRyffYndmOLhM48fSGdkk43mrelqraZli
         hWtBpK+ff39anperbMZFetE1bChT8pnub2MmpKJLQ1i5JXisxO9OQNEZNknY891i2i5F
         7xZVhh0sOSrMAtZxYcEa7fTrUegQhpuyePLFdjLeqjRou3TJvbLpfE1gAsF4sQuyQrBR
         TRamTOi8wRMvt2VmiYkhcs2lBUpxRSZ6iS1A1hWLP5VPIt2fqwqlIYk14swHM6P3lWnY
         i1BD1lWHLnoI2U+vPxD1z+UEnPONnxeS3Z8GHRV/gyvkbx58Cu8wEDTA+YywkWcjNCep
         P0fQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qw6j5mpw;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Aj2u/VB95LIn99gkVno+FJnexBCaY9AFf7KOoF/mav4=;
        b=do6yXnTw/VOvkVjMiJf3oJEIFWrpOuROzR3qYIRRq5DJSLo+/Yxxs6QyYEH85xjFBX
         2zE0eS1mczQ3K4oIVFtSju5meh1vr8aqZtu+zI42ckBnWRi5KMNMohdGcjjcrwKQY5nx
         8as7chdkffaZakinyISimJ6akX4G59yzUqQQs4Nmfh4oOGWCTTFb77CdkmhXgowjgIWZ
         6sCShQ8MA9SF/1qQPG5b7YojtOg5DRQKptO3MM/gYFGm0Z/D8mPWQHOYpQ6/MN1SvCrS
         e3FP3P6P8hjb443gqEl1X3vnBb2+Bu1l2UsQsYnOwV5vqpOXmwZOTipo9mH9OCbcwos2
         IYeQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Aj2u/VB95LIn99gkVno+FJnexBCaY9AFf7KOoF/mav4=;
        b=JO0C8dz+fLC8bqo8HuBCcnpyZy0oe/Un7Fv75gzFCgdzwQIwDtSAHAtmJcq/ywYn5B
         FSF8G1rpi2ojbHsHSRgFmH/ZHPvo2aUvynU5vYtp9VDHhKPzhLgHOBDAfeDSYkREWEsy
         pP53NONTwm2+31PQgl4nI5rSgrdnVeydbHuruHNzw+exOJasrTpbwX++rWwfyVo5qr6P
         E5IGqWhIGy5Fxx5c+oN1SfFcA7afQqb9mf7UBFCJ51d6E2ZX3V32SWOPQjZlUufkEPGb
         QQuT4CUFMY0yyhV7yRKxevLDEE4az0LJtF6Qr2LsVR4JvbGpRmWLXsDj6Rg0ZrMZjckb
         lN8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Aj2u/VB95LIn99gkVno+FJnexBCaY9AFf7KOoF/mav4=;
        b=sSNlcpfJwrcphb8Hy6dYedmoFmcKvBIgNMm0YTNXajI9e7jl2tNddyt+gAX5aTLfzz
         awEMsPilI6fw4MYY4nfdleDVxqs+pKtznAu2uVo8hC29KnQfUq+tODSBQO0Vm9aNhwBE
         r2XwRQeCysmynz6m9WsGwn80fQ9X38cseBJY+WN4KYInTEWrI/uXzNNuvGwoRYWoyOAq
         wxFkpq2wzzyjhw4ns/5UjiHoP/Z+bSfN0ebw3uYlA6U7Nk9ghbpKNsR6vgqtd0M4CBLq
         vU2h6PStQKziDpQbHRwGSP+eocIM4xcH52HNwAyZHNM0jNvwyVdv9ruodQHdidilk/JP
         sHuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVkFhljX9L98BXZg8abvfIBUs6BfJBMny9E/QybhI3YK099D6pk
	frCt/KMAWSvqutlSYK81Ma4=
X-Google-Smtp-Source: APXvYqzcfI6nFS+o24puGrH3t5zlue4SYJr1fP1foC2kRDfswnsLe1FeM6LrZJaWl4ZrnglE2wJugA==
X-Received: by 2002:a2e:9a84:: with SMTP id p4mr1951145lji.22.1556814700641;
        Thu, 02 May 2019 09:31:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:3802:: with SMTP id f2ls253387lfa.0.gmail; Thu, 02 May
 2019 09:31:40 -0700 (PDT)
X-Received: by 2002:a19:e01b:: with SMTP id x27mr2483987lfg.14.1556814700167;
        Thu, 02 May 2019 09:31:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556814700; cv=none;
        d=google.com; s=arc-20160816;
        b=YA/hUT0TNiqy89KQyKUgPXt2oZY9AnZu+zOwWO7tWh+pQfH5RczbiTYSVCfN3qr2hm
         4EMDbw/Y44vsGiS/ZN3edVYT54ZHKph/65/YjA1+iWkXiCyzwWQLFF9HM2OhcaqWhWzX
         d2AvLJRSyxry3QquMskqmDoA7Xe7B4OBOzAmkuW6O/C2RIJyUyEzNktUhviY0nq1rEYo
         63VU2YpemqheGaiw+PdrGdOYitPLwkD8J9OZF+kHdFBjw6DfivFtuVe07o643RYaR4dq
         M7Aav1O1gLxMtHbty18JyBgaNchnc3Qg3WSjGlWZLR/H/6Y7lALOlyl2qbjoOq/eK6Au
         wzew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7Oy1RG3BUKEsx4VUlFgLOKgTT7HGDm6BmTdCPYEVHzI=;
        b=nTcx4PupTHDZPTwF1mwABQv+Iidz96f6RulUY3F8VEVL3eYFDTxCGriQjpRm6l88Uc
         p2ejv7Oz9z7a6MbpagHh7F/J6nVHGnHwnajDXNwKmH0tek/c2O+KOeh8hdS4sC4Tlgid
         kWJSmdRd8uC6LU3vyqE39QFQRjp3kqhkpc+4QGKQ2OmA64UCHjX3L45Fan7O/JRLl/wM
         MMzsj5i3yL/LxK5bOf7bQKD/wZmEoPir5m5tQMvgJbG2NfsDC3Lxl91LDa5OmQzloNp4
         pE5MnkQ0i36ozJNCYBhJG0FjOIrJtAt9+LMhoJI5GpEPZNHpP8GeoyHM9UyjGd2ggtkq
         18XQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qw6j5mpw;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x531.google.com (mail-ed1-x531.google.com. [2a00:1450:4864:20::531])
        by gmr-mx.google.com with ESMTPS id h68si840836lfh.3.2019.05.02.09.31.40
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 May 2019 09:31:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of natechancellor@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) client-ip=2a00:1450:4864:20::531;
Received: by mail-ed1-x531.google.com with SMTP id n17so2694646edb.0;
        Thu, 02 May 2019 09:31:40 -0700 (PDT)
X-Received: by 2002:a17:906:5fd7:: with SMTP id k23mr2318906ejv.201.1556814699691;
        Thu, 02 May 2019 09:31:39 -0700 (PDT)
Received: from localhost.localdomain ([2a01:4f9:2b:2b84::2])
        by smtp.gmail.com with ESMTPSA id oq25sm7460093ejb.46.2019.05.02.09.31.38
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 May 2019 09:31:38 -0700 (PDT)
From: Nathan Chancellor <natechancellor@gmail.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Nick Desaulniers <ndesaulniers@google.com>,
	clang-built-linux@googlegroups.com,
	Nathan Chancellor <natechancellor@gmail.com>
Subject: [PATCH v2] kasan: Initialize tag to 0xff in __kasan_kmalloc
Date: Thu,  2 May 2019 09:30:58 -0700
Message-Id: <20190502163057.6603-1-natechancellor@gmail.com>
X-Mailer: git-send-email 2.21.0
In-Reply-To: <20190502153538.2326-1-natechancellor@gmail.com>
References: <20190502153538.2326-1-natechancellor@gmail.com>
MIME-Version: 1.0
X-Patchwork-Bot: notify
X-Original-Sender: natechancellor@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=qw6j5mpw;       spf=pass
 (google.com: domain of natechancellor@gmail.com designates
 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

When building with -Wuninitialized and CONFIG_KASAN_SW_TAGS unset, Clang
warns:

mm/kasan/common.c:484:40: warning: variable 'tag' is uninitialized when
used here [-Wuninitialized]
        kasan_unpoison_shadow(set_tag(object, tag), size);
                                              ^~~

set_tag ignores tag in this configuration but clang doesn't realize it
at this point in its pipeline, as it points to arch_kasan_set_tag as
being the point where it is used, which will later be expanded to
(void *)(object) without a use of tag. Initialize tag to 0xff, as it
removes this warning and doesn't change the meaning of the code.

Link: https://github.com/ClangBuiltLinux/linux/issues/465
Signed-off-by: Nathan Chancellor <natechancellor@gmail.com>
---

v1 -> v2:

* Initialize tag to 0xff at Andrey's request

 mm/kasan/common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 36afcf64e016..242fdc01aaa9 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -464,7 +464,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 {
 	unsigned long redzone_start;
 	unsigned long redzone_end;
-	u8 tag;
+	u8 tag = 0xff;
 
 	if (gfpflags_allow_blocking(flags))
 		quarantine_reduce();
-- 
2.21.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190502163057.6603-1-natechancellor%40gmail.com.
For more options, visit https://groups.google.com/d/optout.
