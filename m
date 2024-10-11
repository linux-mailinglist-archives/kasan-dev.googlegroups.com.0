Return-Path: <kasan-dev+bncBCMPTDOCVYOBBBFAUS4AMGQEGN2TQOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id CEAD599A2F3
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 13:46:13 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3a3ba4fcf24sf1622205ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 04:46:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728647172; cv=pass;
        d=google.com; s=arc-20240605;
        b=knEhw2NZgkSroNIBBZBMK7v5KQOMrghFQGyOfMP5vuik6DVUCQnTuKj/IWZ44aT35H
         NxXKofmQsKAULA53QrYMbc+/25O4shsC8NpFYyR/hk8REKVt2O7Qa3SJk0V329ZaCWtu
         WzJcCS7yesTv+1oWGUR5FYFW7KrBZ9pH1KIymU4T6oEuectGWKCBgt/OIY4cYUrKGElt
         Y/swGsZhgpa9y9JBohaFs3IKU8qZ8hhzzY5OVaj8NraZYqTNxWlGR2PUKJ5KpaUzPxNU
         6edlswNy8SFIuVf8uRU8SWqKUQ8Y1OI5pZSCgtdRNv6oFvfK1+H+2KRbXeApUaSgokEh
         Da+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=rBW+C7zfHNUbjYCK6x9bKMZ7aTWiA6rYvHs7XZi6DT0=;
        fh=f9a4qekzFUzDrHcb3vQkW/JLEAVOKtUDLeP/+iFZ/fQ=;
        b=RgVo9ax8xFwtjKbLi4e1iu3wasY3xJ25vLWt1EU3SekSCAugXVOvNxLW9ljhL8+kp4
         bV7rZ3Xxj45nfPIOy7HBAeyDh4nQTwutTmT4nHkMksZe3pzWP/PCN0UnIAnyX5YsGsjq
         NYGu0neAjYAB5Z18TVPxSioI2bNHmgLpGZ8DaE1wszPbu50f8deyUoxLLzmJ1P1XVLnS
         SMNQ6VojFxIaz1hxJFEIowMSbW6zMEWhwvmfqPIWkCBx+JkASAJrlXVRbo+pBf/c86kF
         IjaKOCC/aejNcHIuDPIE0BzgcxN48foMbK97YDohIlJ/hDy82FBbpzo4gKzS/4Cx17ik
         UmRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LmNnt7Ab;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728647172; x=1729251972; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rBW+C7zfHNUbjYCK6x9bKMZ7aTWiA6rYvHs7XZi6DT0=;
        b=N7BtFZSVHb8Jc9KGDLVKnUP/j29yZbXs81ePA1LKBS6FoKVwdEEP8PQjLChtz9upSl
         J0Q6AIz9N4/rRkwozRXQZ62sr4RxN6K0rjKx8joGW4EoElBFhlf7HEfMax7lVdMQReCq
         /iMaD7jbGnvFv/RRF20lXvSzG1K8JpCUOz6lLLtLviuFCUg7AYzFFiH1/riHV0kXiI1/
         Ptpf+xqI3uhaWFAJ5Ypq0A39ev2T8vaKJS0djQTJI7NWKUnRfwSVdrIIas3gO/JdkyQJ
         GFNPHvZZFBof2OcewoYGEKeVOqy7ym6EIxMQgRr3U4VKnyST7Yx4fdyVGRRC7XCloHdf
         EgSA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728647172; x=1729251972; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rBW+C7zfHNUbjYCK6x9bKMZ7aTWiA6rYvHs7XZi6DT0=;
        b=AV4hgterOmdra0CR5KTW5ge4x3Abyb8Pg6K2viYmt5ylRCo7LTtPAffztLP39OVs3D
         tyuXv8DU3IUxKspmN0PAQniRDGEmqSz7t8DC/CWFoMnJNtdq4mL6gFvORXfyqlQc3bxP
         a1A1dTYNyvileYHdizMuCVQHdGCDUyaDwYRwgWl3YMhI9kml9l9Ng4GdjzcJEjgj7LAQ
         Ai3lIQQtnrz+xFO7/lqPuNUGDUfSzxgBKGzS8n1U1+yCGuvkay/+K7/wI9aRFfk67J3O
         Tw5lfulHPP/0YCSgEPkLoIkd1f+YYmOELG7oceUqVKkFDM1gP3PvXBcfL5JGzr1+Cq/F
         y9ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728647172; x=1729251972;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rBW+C7zfHNUbjYCK6x9bKMZ7aTWiA6rYvHs7XZi6DT0=;
        b=vIKs4jhX0lrJkTVOl6aTEsffztG8Dw2Yq+dqtDdwvJGPXAKvnnz1ZHvvIVxNFYBnAj
         gVGmexQgYGfbakwjhuxDmI2Zfyc0MKzDYpMI6ciTJ8B8rTiGM/pdRbtoXJvHxgR8mVbM
         /ndW5ywYcBD3yqB0TFqCTu4O3YeUuzQaaOtsS9iU7VMsJhUTf6H8KtuuBBeeqz5ZIhtj
         CXbHe6+7NnNjFVTWITFJKIKM+Gn/PXZgdQBgLlwZIHugKH7S0cfg89cSc6eVNd9rmd25
         cWx53Ry0Zr1viDp7zEiCLB+imbkHO6UNm/SqudQUwjkyiO6rwNU4mJvJrP5WIpx87+ao
         rVrA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX35gJYWQ1NpnbjHk4M9AvXukpDaUKqyG4SCmC8+D32XkkJ1HuVg4PfBzmOgZ/dwlx1Yqrc0A==@lfdr.de
X-Gm-Message-State: AOJu0YwXLR4r2KEQu965W40jUEr9kHKJmPDvtQoM9dro9upMYsjCLYcR
	9p7VQs35gJtyhU3BC2lm9eoPtUpmYs9IHQjMFLKo4VhtsERizjR6
X-Google-Smtp-Source: AGHT+IF/8agZzs7pDMHO0C+jg1cpsRjDV5Bb+baxivwgjNYBKi+yuDvGVdalp44W2A+R9POWz7TJ2A==
X-Received: by 2002:a05:6e02:1a8d:b0:3a0:b384:219b with SMTP id e9e14a558f8ab-3a3b6051030mr16220145ab.26.1728647172324;
        Fri, 11 Oct 2024 04:46:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1ca9:b0:3a0:cadb:1448 with SMTP id
 e9e14a558f8ab-3a3a736d762ls11748785ab.0.-pod-prod-02-us; Fri, 11 Oct 2024
 04:46:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX18lBQmj5R8HmXRdp3sMjuS82YOCSoe7oSnR93jEXPw6b4LrslMd0msQzVGxuSeNGQlkUgJiIaDVI=@googlegroups.com
X-Received: by 2002:a05:6e02:168a:b0:3a2:f7b1:2f89 with SMTP id e9e14a558f8ab-3a3b6022e6cmr17821245ab.18.1728647171404;
        Fri, 11 Oct 2024 04:46:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728647171; cv=none;
        d=google.com; s=arc-20240605;
        b=b28yXNYc2opHBVqWAdZbP4NaBc1RNQ6UN7s1WHI6rbXLTATWAM7O0yfb/20Gl1EeUH
         P3xDQZ5QzD203MgVQIAmhZKPqfL1XtGYv4xfVL+f18VyakMUys4Qp+0gPwxElNHtRIPJ
         WQkxKdMOXS2T3Si71Ba+y57sDH2DVAHkGthpq7M7HI0YGsAwbT82dUOhGkZ4vm7rwSsG
         JLPFo5EhE81fy5x+YjHFJPEO2e1yd6oJHw37HGfRldn9KcNGBNYAYif5gv+Fx3dWWEy6
         dNfjlJp9XLVHGTVQKxDIP2ErlIBkhh0nfRON2gEW7wtc5x6qdJPhEyY+9aNnDxgIvxW5
         VpcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=dh0JsT1PknEj7URfHm3XckV7bx4afAgP2FtAaB0E9bA=;
        fh=vApUG8Tv1h44iTCqOvQw08FUSph4AyFVKh1k66G7g0U=;
        b=QxT3u6Dr0HW1QoS2KDJWDmMUSmVY0gy1Nsun8lNhUNt5MvRRphskcnGiv/4Cj1K5zr
         LqLrmF91tD6mI1qfUMoYdVzzX+V1uVlpXNi2viZ2f5NtR/1d1aV02SPh6xdBuadIAAmR
         1x562CKdtSDsVjkidu3RmS/5OUJzhzTyARr1SqKn5DYTH4LFhOJ/wTpcs4R0mVHva/t+
         /vW9dWCe8o/qDbd3I2yitu60doRnqnXCDYFINqzyx55WC0Iub4eaFKTjLxfOkFGOtHji
         D5Cb8Wg1M7+czGojpUQl9aOYmKxNQCbBpP/PHFBcApXmcaNmqe12JLPtiPcswcPxG41U
         W/ww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LmNnt7Ab;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3a3afdac4fcsi1417045ab.1.2024.10.11.04.46.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Oct 2024 04:46:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-2e2b720a0bbso318519a91.1
        for <kasan-dev@googlegroups.com>; Fri, 11 Oct 2024 04:46:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXBBmDYFkkgQJ2/s8/SoNwEe/KFtOLHWR6XDARdL+NeTblQ9sp4HqS67lZr2Zww5pEvWOISrH+ciSU=@googlegroups.com
X-Received: by 2002:a17:90b:3509:b0:2e2:de92:2d52 with SMTP id 98e67ed59e1d1-2e2f0e0403amr1317867a91.9.1728647170482;
        Fri, 11 Oct 2024 04:46:10 -0700 (PDT)
Received: from ice.. ([171.76.87.218])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e2f6e9ec0esm1106025a91.28.2024.10.11.04.46.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Oct 2024 04:46:10 -0700 (PDT)
From: Nihar Chaithanya <niharchaithanya@gmail.com>
To: ryabinin.a.a@gmail.com
Cc: andreyknvl@gmail.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	skhan@linuxfoundation.org,
	Nihar Chaithanya <niharchaithanya@gmail.com>,
	kernel test robot <lkp@intel.com>
Subject: [PATCH v3] mm:kasan: fix sparse warnings: Should it be static?
Date: Fri, 11 Oct 2024 17:15:38 +0530
Message-Id: <20241011114537.35664-1-niharchaithanya@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: niharchaithanya@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LmNnt7Ab;       spf=pass
 (google.com: domain of niharchaithanya@gmail.com designates
 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Yes, when making the global variables kasan_ptr_result and
kasan_int_result as static volatile, the warnings are removed and
the variable and assignments are retained, but when just static is
used I understand that it might be optimized.

Add a fix making the global varaibles - static volatile, removing the
warnings:
mm/kasan/kasan_test.c:36:6: warning: symbol 'kasan_ptr_result' was not declared. Should it be static?
mm/kasan/kasan_test.c:37:5: warning: symbol 'kasan_int_result' was not declared. Should it be static?

Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202312261010.o0lRiI9b-lkp@intel.com/
Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
---
v1 -> v2: Used the aproach of making global variables static to resolve the
warnings instead of local declarations.

v2 -> v3: Making the global variables static volatile to resolve the
warnings.

Link to v1: https://lore.kernel.org/all/20241011033604.266084-1-niharchaithanya@gmail.com/
Link to v2: https://lore.kernel.org/all/20241011095259.17345-1-niharchaithanya@gmail.com/

 mm/kasan/kasan_test_c.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index a181e4780d9d..7884b46a1e71 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -45,8 +45,8 @@ static struct {
  * Some tests use these global variables to store return values from function
  * calls that could otherwise be eliminated by the compiler as dead code.
  */
-void *kasan_ptr_result;
-int kasan_int_result;
+static volatile void *kasan_ptr_result;
+static volatile int kasan_int_result;
 
 /* Probe for console output: obtains test_status lines of interest. */
 static void probe_console(void *ignore, const char *buf, size_t len)
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241011114537.35664-1-niharchaithanya%40gmail.com.
