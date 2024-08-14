Return-Path: <kasan-dev+bncBCMIFTP47IJBBQXC6G2QMGQEI2K5POY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id AD49F951727
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:56:35 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5d5c7700d4esf6508876eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:56:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723625794; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZdcH4cTRHqQoYQzha+9BGUalAqpuKi9ExphD7/I6kmPpZhmhRZOv6bgv1/uaz0zPi9
         RZ3dNMtPbNGfJxjf4uiCW4CgySYjSQsj8hiIZMBTC025AEpITXzVM/57tFYqyoeKeWYv
         vp/OCmG++S5FzSeQ9R31z43IRUgZZgEDGPT4VsXjFhNzn+KmPaZp1TECGk6rTqm5KF1J
         U5zKO0B2QAakb0VRBcbE2nbr2hv/bEZVQCqtyQIXvBUo2E2njGPs69rHlx/wiOWdSpey
         xAADnNrt3lrlbSAdQgfjVrrZguWLJDLTiPZ5byqtZHzILngGIfs971EPPBwoR7poLN9A
         SvUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=IffvqrvwxEi5gaA3dvO7FO3jTydimf0/x7IYgWEvXd0=;
        fh=KOnNkLnwH01YxmElRhIOyHEE0eoYnITqa92zCzy4Hlk=;
        b=UbltxY5H6ttMoDvH+beIsbEE7DODddPL+Ncv27AstqNOojEM6dzqUgAuPeL6EUkHfL
         I0V5UzmcAmuxp8KIjNBeasPr4XJROKMI+cOB1QIiAHl3wivLikoIdgGlMNUvSP9MP5gY
         7vpzVCC5XmAgaLNuakDqQU9adN0/yweio+eDAIddfQeMXG/R2FOaC/nGrM6JM8l6pN91
         dF4jPBjLVf3JKUegTDdVugqA9fagROb+soEQtjh2NkjitH1lBcUO9prHWA57Ki5vCBUc
         EP5oP/pyoCFTVn3A3TMEyNk6LP03OXK44XnPa3FWgZEqEaACIDq9atFRmYV3n49HL4Ll
         axtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=lC764Zpf;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723625794; x=1724230594; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=IffvqrvwxEi5gaA3dvO7FO3jTydimf0/x7IYgWEvXd0=;
        b=ZDHHHiiQGNmAMlyCpxlKRTRDfIqJNiFWrwdwDcIwdP/smZ7aXp4dkNkc+ElW7zcLN1
         SY1H6yMUfecpWsw14B3tdVDJl/TIpkl1nXmazUQpIeiwTKmNVK64OKVukwCnWHKET6iF
         cz7twjsNp8cVZj3ek5hdPZQkDEi/ffrW5C6bsWydBWEHGyQRVtU8FfUJn9uDt9N9Qfhi
         oivUxFDb3pRgeo/M6FT9+mZXafMNMjhYmun1x8rMh1XX+y6biRsTscfUps9fEUH3/NSH
         OEuSAOkYjsY48sqhUwF6qO+AHmB186DA+l9be948qQvHA5sAi3eKl9VepgGl7dbisbpu
         AB4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723625794; x=1724230594;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IffvqrvwxEi5gaA3dvO7FO3jTydimf0/x7IYgWEvXd0=;
        b=VRHX2fI2AFm4PCewDZkQ/R32pciustsL8pD0oa9W4tFTAOUnZ4J+kORq0NKHG/dP8+
         vaDRN9la1DYW4b6f+95xmoYWA5qis1CRKYNQFUsWzo2ZyVxQutjCjx6BCvd1HpKgIuaV
         kPYhuocRSS7IN2GG1Yzuvvuh0PfYG6mQCrjJO5adq+W/5SpZqYo6cPO8yguExPKV0cHB
         NQw2DawzMGyMZFRGNhCRMDUS8phN7EJa99Ilc5ZNtiuCYslTVdDa9uHSs9dYI3x90czn
         zq/U75ALVJrvncBGCf0DrhFunOuGCTgCOUfrSmTv7uc9mNgmvo+PGBBL/aIKAdUT1kaY
         8AqQ==
X-Forwarded-Encrypted: i=2; AJvYcCWRVZRHR2IVI7OfZh1BJh5+eDA8MEOiL7GQfE2gmhqYCDnJOOa/KXzK0zVXRzMjZmiLShsZK8CQhGlzbnT8YmbOBU3tDu2lRg==
X-Gm-Message-State: AOJu0YzYtwG51Bc/FP6UIk5F12qkvmIbRlhsABNCyZ0dLpZRfkQgcocs
	YlBXrcv85PkGrYJF/Fq18qLs1txXHPIwuXY2TtOxDHybupbOuHrB
X-Google-Smtp-Source: AGHT+IFNX/GJpXVGaJURTAWMimw132yyhJ58qJLODo9Lskuw3IRUsTl8M6EvR13EOrT2nz8WEZjj3g==
X-Received: by 2002:a05:6820:1c85:b0:5d5:b226:2ff5 with SMTP id 006d021491bc7-5da7c48c174mr2793667eaf.0.1723625794381;
        Wed, 14 Aug 2024 01:56:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:dbc7:0:b0:5d8:326e:807c with SMTP id 006d021491bc7-5d85129b81cls6700351eaf.1.-pod-prod-08-us;
 Wed, 14 Aug 2024 01:56:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX6iPiPS7c+sSUpMNTo3xUFiLTeSkXM6cr0G9EqAOalZ5SZ75xfRaZhUh8PqPghFqYg0pH602VGvgJaV/zX84M4rvdHXnqpraZDQg==
X-Received: by 2002:a05:6820:616:b0:5c4:2497:c92d with SMTP id 006d021491bc7-5da7c5cab44mr2687249eaf.2.1723625793638;
        Wed, 14 Aug 2024 01:56:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723625793; cv=none;
        d=google.com; s=arc-20160816;
        b=i6rhBttBkT5wpg6ITJU2BJ8UkcK6rDWR8L6uu317orvscYu0ITaC2JbOauc59+cfs4
         dyaDdzGoO9TieyQ34akb0Y4iRba6BCPXGLJdgxTuG4hBB3CNeqCq14vcyteRAJTZi3XK
         GqHr9Q7VbiidLOPZH+xHBVu27TaMIb6kVUy0q+5T951nFulq4hCh/lRAmer5StRmKRcU
         n5z8MNgBXIIgna83vNL+hzXuFyOsQ7ayq5gAYon8BVmFH8qbs4DP0pVebKNe8ipumwku
         CcqwrHTDwZzOoFxCgHWy+ewTSbh7hMdVjcHCOvIDdZogkz9FLB9k4ETq0jSXCp+Hced9
         5Zsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9hz49lwxt/ore9sEZ/uYZptf0bZHlG9fVMF8g6BZbdk=;
        fh=CSRkfeoX8QOX9tz3qLB2ZffWI78WubmvHGVfWnsFCw8=;
        b=BmTRWYMZlFQ/gULvDxDNDpcSAU/dWnPrzInjgi55PBlkgFRrpiG230S+10lnEuYcVo
         Qc1AjLIzMEohb+g2JP/ssskvOp3L1CzHStRl7TjJMyHq1F0LfEMAryv6VriSXwjDRRkK
         At9GrIDa8E2C75+3cbeWejemUnZqbqUEH9UTO7C5aD+wVdcCSe2xh6errmHOp0qxOYa2
         Kdc65QUeQ38hvOG+LGxI7Nvup+hy7ZCRACtCoFyRJgld5eLRjc11+OneF0oDwuu+Oh2E
         5Ex2DzhqMJmpzhnMX5xe0bjpPkOHmulJZ/WvlvRPAdznKYFnx2iwtd+uoc76Zme/2EYT
         uQJQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=lC764Zpf;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5da3e715ad0si359835eaf.2.2024.08.14.01.56.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:56:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-201cd78c6a3so14079695ad.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:56:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXUl5lCC/Wei9wDoL9xFagPQ5Al4U2Dg7AZmKDz6XIf5504v/I36hf4lyslmlRESfZriUuv6UeZP6C+kl1dmh/+MryX8Ynoy3WNtA==
X-Received: by 2002:a17:903:1c9:b0:1fc:2ee3:d46f with SMTP id d9443c01a7336-201d638d797mr29420295ad.11.1723625792838;
        Wed, 14 Aug 2024 01:56:32 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd14a7b8sm25439615ad.100.2024.08.14.01.56.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:56:32 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [RFC PATCH 7/7] kasan: sw_tags: Support runtime stack tagging control for RISC-V
Date: Wed, 14 Aug 2024 01:55:35 -0700
Message-ID: <20240814085618.968833-8-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814085618.968833-1-samuel.holland@sifive.com>
References: <20240814085618.968833-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=lC764Zpf;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

This allows the kernel to boot on systems without pointer masking
support when stack tagging is enabled.

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

 mm/kasan/kasan.h       | 2 ++
 mm/kasan/sw_tags.c     | 9 +++++++++
 scripts/Makefile.kasan | 5 +++++
 3 files changed, 16 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index fb2b9ac0659a..01e945cb111d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -630,6 +630,8 @@ void *__asan_memset(void *addr, int c, ssize_t len);
 void *__asan_memmove(void *dest, const void *src, ssize_t len);
 void *__asan_memcpy(void *dest, const void *src, ssize_t len);
 
+u8 __hwasan_generate_tag(void);
+
 void __hwasan_load1_noabort(void *);
 void __hwasan_store1_noabort(void *);
 void __hwasan_load2_noabort(void *);
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 220b5d4c6876..32435d33583a 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -70,6 +70,15 @@ u8 kasan_random_tag(void)
 	return (u8)(state % (KASAN_TAG_MAX + 1));
 }
 
+u8 __hwasan_generate_tag(void)
+{
+	if (!kasan_enabled())
+		return KASAN_TAG_KERNEL;
+
+	return kasan_random_tag();
+}
+EXPORT_SYMBOL(__hwasan_generate_tag);
+
 bool kasan_check_range(const void *addr, size_t size, bool write,
 			unsigned long ret_ip)
 {
diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 390658a2d5b7..f64c1aca3e97 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -73,6 +73,11 @@ ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
 CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
 endif
 
+# RISC-V requires dynamically determining if stack tagging can be enabled.
+ifdef CONFIG_RISCV
+CFLAGS_KASAN += $(call cc-param,hwasan-generate-tags-with-calls=1)
+endif
+
 endif # CONFIG_KASAN_SW_TAGS
 
 export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814085618.968833-8-samuel.holland%40sifive.com.
