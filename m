Return-Path: <kasan-dev+bncBCAP7WGUVIKBBBP25KXQMGQEWQ6DUNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id DD0B9881011
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 11:40:07 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-6e687f8d275sf3482892a34.0
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 03:40:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710931206; cv=pass;
        d=google.com; s=arc-20160816;
        b=erQWOAWiJru2kH29JB4ddAIneVVN9OV3VHaxiKLKi9bdeGEb6b4zCqs6TaQIBU7Nlk
         ANFfdQsLCIsSP1wCkyFu7MjVg7+1IKF06Glx1VlGrZK7C19RYQ+TLwxxiG/S7z+lsc8r
         rVax+c7Z7g1g/DdgZR3Fu7npDakJuT0bpyZr/hMLs7Zd+aNVHQKyOJ3ce/AGeztNCbMo
         7rjvOCqUL39x7rS0+QKfnAfBzwWw/4R1tojjrpuWbFjZ8YjDpBtwkC9FgGhSTDae6Bcy
         1DtJ1i/GQdPSXdT6rXMwOnUeoLsg8HIcKr43hUOtiJcFlR4k6VL4+8+k0LCtwZd26Dam
         KAlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=htoaw2lRp/Qlnjc2tpI9LnqXt4if4n9Gmpx9ecksFDM=;
        fh=tcwfrqhOiA6fvuR0A1ZfOSag7gATFNd0JtlefXFSvq0=;
        b=bGXO1fnEJt3KrSieWc4SJkfvYS6zLmYonrZvcWcwrVScMbl/gdQTy3ZMqYXF5e64jw
         4TfV5IsB5Fml/Pt5p7Nb901tQ8a/polqo2grvCaeylEKL2iL2IGMBmBOeI9gSipBN9l3
         37HDf1Nwqx+L5ojWMd67jQKVKAO7jOSmTH2XTjpKVQaikyiX4Ek8v4LBWqC9/tkbMGCF
         LA6tdabN7Pz8GlhQFeFrIMhiBR9DkeSAko72c/+HwvpXxlVi3UaJQEuRMe77tuuBKMz3
         lX+58O1IZKpEhmf2igmw4E4v5Denc/D0pFQ5/OkeGJDZkS7CWGQV++8q/EZxToMF1VwQ
         ZpNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710931206; x=1711536006; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=htoaw2lRp/Qlnjc2tpI9LnqXt4if4n9Gmpx9ecksFDM=;
        b=mQ3ojZKlV91MyXkui6yoDGHzmYIvk1M/HUPQiAHjWqdJ1lT4aerXj++1CmqIDI95Zr
         L2deJyw/Y24iLuc/INWGAleKyr8R1FfECzyexeimnX2WF4wOthulGOeLT15/XaoQC/Kc
         t7wGH9qMqa+eW/f1Rmc8S2YHhaIMQXpwgHLGslRJdVuwDxC6YlYoXFHYDj+CuUy/HUfx
         YPXQQSXCbxkDqZgo0NY1bQ0Uhke2KSK/sMfujfjx+M8xidr0ezB0oUNeH0/xnbGGxZoG
         YTgXi0gs7PnE/bAYxrN66KMp8aFGout5L6kV7docQCOf5X4wijxNwfs4ytSJA2C80RJD
         4ZRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710931206; x=1711536006;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=htoaw2lRp/Qlnjc2tpI9LnqXt4if4n9Gmpx9ecksFDM=;
        b=qmOz/0j4jv3u/i+jFvOD3m1YURtRnY/J7IX0bMyjuNm+cJX/aIq6/kM6dnHMW/cKhw
         B0MFq7w6l/C4P2c9NfIjhVKUBnhmBVa//J/BbClxQV6mkU0hxcDCUCJEEchqvvzZLPT3
         cYvciMHoBDRuRG/gHjOfL73i/WXMXrccHN61E8LVgVIu0AM3PHZrkKupXuTZ05e2grJV
         dlDDOCbTGSYKVJl7kR+KyMQFildq07yZDu7L9VcQNzF3f14MnQyOFXRCrb8PBHLsBXKm
         EgR3WT0o2uZjLxh2UaQ1T/v9SIYcWJXO+M3msInoBeBIeV1kAkylsNkNyoY9a2RmCvCL
         /i2A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXzzV6AiHBm1NHp/wwdQZOzdv9HwjKWDe5tkZoPGiuMy7bn5p6UR5+Rze8D0TYMffuA4mM7wayiqx5mggqpBe5mXdyB1wf5Q==
X-Gm-Message-State: AOJu0YzRdWudMt1geHV+eqQ4TO3HFZ1DYRQv5/bC9SXhgjlOJAkNiwcc
	kMnIrmuWvi8ti8RKs3r1KlwzidaaNKKo1e2NjpjOFTBBRM1ZymCV
X-Google-Smtp-Source: AGHT+IHlA3he782nR48Rg4HzyRdUcI6O1oGr71I0R8PL5iKlRz45FDiDql2kRTJ0ko2CYvxUg7jWKA==
X-Received: by 2002:a05:6870:6192:b0:220:8d82:3838 with SMTP id a18-20020a056870619200b002208d823838mr18747135oah.28.1710931206278;
        Wed, 20 Mar 2024 03:40:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a115:b0:221:d814:2777 with SMTP id
 m21-20020a056870a11500b00221d8142777ls4856746oae.1.-pod-prod-04-us; Wed, 20
 Mar 2024 03:40:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWrk3seqdvpScB9d66HUyJsRlZUohJoIJUioa1HVuc51kt3p+elPNMEnAxpvO56k4qTkN03smsfqk/CwFQSQ5nY1lt//gg9qkSydg==
X-Received: by 2002:a05:6808:171c:b0:3c1:41fc:d012 with SMTP id bc28-20020a056808171c00b003c141fcd012mr20784808oib.34.1710931205282;
        Wed, 20 Mar 2024 03:40:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710931205; cv=none;
        d=google.com; s=arc-20160816;
        b=yfr7TVsRPsGJK9UtHlQhm+sKPDb29C3TRyPL0uDQSnyn1BwU+tOFU0GTyi8IHSePRl
         v600vp6Y3QCSazlVb3g3olK1JetxbdT7XDBNnzYVeXifE8ePwwFiLrfaUCWu2BfVB002
         4+OiS0XFHjgv+fHbwlw4EJ4aWHL0scAs4sQcKSYeKe8V5WtgxMB+XLmnJ35KoC0w0N6j
         ys+aC7ESQ/BrUfjuqxhQy+u+FsLsDAwMuJHf1f1tTNZvB6rwP7z1j0TA31D0BeMaIDpB
         lWjd3Fkoyk5jN1MfadqRPGCfF50LDcHBVizZ5blwPOngP2xN6wRylPnd7gIoEhSDwgiU
         kPzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=+71EL7yHyPxbE5mLWlDHn0FGrnDSG2rmWvmbU7hrWMI=;
        fh=MarApkI6h53pA3e6zT8M9A/C1Tmi4WnacIPwae9cuNw=;
        b=c0pP6qV3YuZ+pwiOVrtqxIbEldwE0d2GD8R/cHGJSspLMIW4P4l+FPL37QrQ0OsjQC
         Zp+NtuTt4EwhwXTmvIZ/0A19O0ypmN4SmWiUbhmPrh3aHk1faoE1aijfskTz/xc9BViZ
         attT8846G+YKQlVwX05KBgMUAvF+pkvNCBY1wEAq1W2IXF4ZTFQsYtRtYH4hI9jrIXOz
         6w0HeH0AMc5wR9JbyQn9IyhRxCT0Yy9sZc8+kkrX/rpQEBp5/5N4CibJBt294U8kgb1P
         hQRbL/Eqw54J9WcEctWRAIlI8TRxrPaGQCcESy6ZJWVFpYNh1k6ppcU2GvtkUcACwvhc
         Ny2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id w20-20020a056808141400b003c39f1a5335si120001oiv.1.2024.03.20.03.40.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Mar 2024 03:40:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav313.sakura.ne.jp (fsav313.sakura.ne.jp [153.120.85.144])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 42KAdo0k048716;
	Wed, 20 Mar 2024 19:39:50 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav313.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav313.sakura.ne.jp);
 Wed, 20 Mar 2024 19:39:50 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav313.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 42KAdoUV048713
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Wed, 20 Mar 2024 19:39:50 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <dce41a35-aa2a-4e34-944b-7a6879f07448@I-love.SAKURA.ne.jp>
Date: Wed, 20 Mar 2024 19:39:49 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 3/3] x86: call instrumentation hooks from copy_mc.c
Content-Language: en-US
To: Alexander Potapenko <glider@google.com>
Cc: akpm@linux-foundation.org, linux-kernel@vger.kernel.org,
        linux-mm@kvack.org, kasan-dev@googlegroups.com, tglx@linutronix.de,
        x86@kernel.org, Linus Torvalds <torvalds@linux-foundation.org>,
        Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>
References: <20240319163656.2100766-1-glider@google.com>
 <20240319163656.2100766-3-glider@google.com>
 <f9a8a442-0ff2-4da9-af4d-3d0e2805c4a7@I-love.SAKURA.ne.jp>
 <CAG_fn=UAsTnuZb+p17X+_LN+wY7Anh3OzjHxMEw9Z-A=sJV0UQ@mail.gmail.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <CAG_fn=UAsTnuZb+p17X+_LN+wY7Anh3OzjHxMEw9Z-A=sJV0UQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates
 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2024/03/20 18:29, Alexander Potapenko wrote:
> But for KASAN/KCSAN we can afford more aggressive checks.
> First, if we postpone them after the actual memory accesses happen,
> the kernel may panic on the invalid access without a decent error
> report.
> Second, even if in a particular case only `len-ret` bytes were copied,
> the caller probably expected both `src` and `dst` to have `len`
> addressable bytes.
> Checking for the whole length in this case is more likely to detect a
> real error than produce a false positive.

KASAN/KCSAN care about whether the requested address range is accessible but
do not care about whether the requested address range was actually accessed?

By the way, we have the same problem for copy_page() and I was thinking about
https://lkml.kernel.org/r/1a817eb5-7cd8-44d6-b409-b3bc3f377cb9@I-love.SAKURA.ne.jp .
But given that instrument_memcpy_{before,after} are added,
how do we want to use instrument_memcpy_{before,after} for copy_page() ?
Should we rename assembly version of copy_page() so that we don't need to use
tricky wrapping like below?

diff --git a/arch/x86/include/asm/page_64.h b/arch/x86/include/asm/page_64.h
index cc6b8e087192..b9b794656880 100644
--- a/arch/x86/include/asm/page_64.h
+++ b/arch/x86/include/asm/page_64.h
@@ -9,6 +9,7 @@
 #include <asm/alternative.h>
 
 #include <linux/kmsan-checks.h>
+#include <linux/instrumented.h>
 
 /* duplicated to the one in bootmem.h */
 extern unsigned long max_pfn;
@@ -59,6 +60,13 @@ static inline void clear_page(void *page)
 }
 
 void copy_page(void *to, void *from);
+#define copy_page(to, from) do {				\
+	void *_to = (to);					\
+	void *_from = (from);					\
+	instrument_memcpy_before(_to, _from, PAGE_SIZE);	\
+	copy_page(_to, _from);					\
+	instrument_memcpy_after(_to, _from, PAGE_SIZE, 0);	\
+} while (0)
 
 #ifdef CONFIG_X86_5LEVEL
 /*


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dce41a35-aa2a-4e34-944b-7a6879f07448%40I-love.SAKURA.ne.jp.
