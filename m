Return-Path: <kasan-dev+bncBCF5XGNWYQBRBEMC6OWQMGQEEHWHC4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EBE4846D94
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Feb 2024 11:16:51 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1d97eb98e1csf235165ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Feb 2024 02:16:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706869009; cv=pass;
        d=google.com; s=arc-20160816;
        b=X1il/c6ersW8J3HN5AhH+3dJrtTKQP+A6/tHckcylSuHTHw0UP+2/JiyU61gP6rcgk
         80ytLO6W2bWxPpkKiOv1IzA3kfmaCBnxN09H55KePmYWUfMEb/WtZ97vc3jksx2xRmJe
         X5B3Kb3gv21MWR6/ujbEQm9gvgaj/bFq2aN07cf2FKZtdskqQTY1lO8TY3GV04i7lgh2
         Q2sQzF6DJcfDtMm/DBLpxNGFXoQ4lG9yoDYsYhQ/6atShEFrAV96uTOquWtk7+bjXx5O
         +hd12Ummk/2yqVLer12pmMRoCN6NOG1Sut6XXCgLgtXJ+F6B3wkO8CCH2C1ncZcYuuOw
         w7IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZY7u3PEdi4UZLS7tFAdnqYucxnQOZ1YdODRl9Ff1n3Y=;
        fh=eyRomMevnGfV+k9Z4WqtinnVIN9Gt7ns4B1p4WqGEAk=;
        b=dFhA9SxoVnSdKQzTBtrChBeaGK8iBxEw8uPHamz20L6kT+w9NZLVnYxcl7A/YSs8yr
         u9QT4kuXnXJLnw9eG/a5U1hCQW05ILZXyt5zwy9C5UiraGjLgsUA2BmUV5TV6dzG74F/
         wO+ayp389y2TJNcdYny/JSow0ZD8YUw7I4xHl2CsRTeBn8WQ/EL9uroB19yfe2Vk/s1h
         TZj9geuNMHQlqMVgtmH2ivgYpvUjMcAzTrO9qZYLwqWRMEFV3D5ZiLGk+vxzvWGmZxLO
         srhHKYmZc4AKSANuVf4bUd49wBJuQvC3i2/IxiPD7YFbzseP/6rWO2yS+/LNGCZiMLIt
         NA+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=fEYgpiAB;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706869009; x=1707473809; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZY7u3PEdi4UZLS7tFAdnqYucxnQOZ1YdODRl9Ff1n3Y=;
        b=S75cqQbehhOm3uMW/EhgVAsIF6awIxp1b7yNn37LYhvX4/rR2kLCofmeEuZJ2Fkizo
         jNQEW9jR05bgKoxJ+AtFvgh7e6OXUXxMEUDfNd+lco1gU1XgSS11e/AqW4kCza1yCUly
         tzHILgkKgXPXYTL2cXmDv4M8DdXQtw1trC5hxfxe2TQy969Zx5SC+5A1tfnm9gf3oZOw
         B/Br8XLw0ilSIrMXA+HCnkv8x4ds/BbEc34ZteMFeRdDbAUe3v+Pk2wbsak2WhNE4UTT
         K8SB+hjYG/oniVpr41WNMZOzO0zzP2hMym41C03qEN7DN3oThpUpin33NNH37wQy+0oC
         Hdzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706869009; x=1707473809;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZY7u3PEdi4UZLS7tFAdnqYucxnQOZ1YdODRl9Ff1n3Y=;
        b=i7rW6rWDcuA/6Dohi14xs5Rxk+z7giYq4sTqY1b6rb/jrbCd3En+cUAZ84kTJToJTH
         Sgyxu00UzB6A5ExCoqc52XKIfEDduDYANyQGhULLP5SrOKILwySh/9YZCpM8DmqQSWtc
         Y9Uw/zQDhtAl4dH+ofePTnnzQNTPzg8VOi7mhTlCZvDbrROBRoWYMLk8iX22PqhAQYCa
         m6CWQI0UF8lQnuUk0/c7o13T6a9k+AKgVLkQaZd+wvkvu/ebJIhzxbislnsnl5CJXzqj
         qWRHD5TpoAtrauOXrHIYTwOU+jEwO4cs4CEVk3siBQKCVlyUIgVbcLsw2vXS4DHxedfI
         Wdlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzApKdXw/AQ3oMtWGtK38nuVykJuyV8z1EH2PyO9RMokuya3FX5
	PnGudujGHmw291S3r/8E+ZYgn/xe2FnlZ4rYpCBB7oUmgClzm0jt
X-Google-Smtp-Source: AGHT+IFL9PUFbqxAS9lsj1qMa7tvwpcusPHI42FMilOqnSx1SviLT/VCpWBnUmxJurHRRv5vM6jH9A==
X-Received: by 2002:a17:902:eac6:b0:1d9:4834:e1b8 with SMTP id p6-20020a170902eac600b001d94834e1b8mr4502347pld.33.1706869009399;
        Fri, 02 Feb 2024 02:16:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:48f:b0:1d4:dff3:504 with SMTP id jj15-20020a170903048f00b001d4dff30504ls1202943plb.2.-pod-prod-03-us;
 Fri, 02 Feb 2024 02:16:48 -0800 (PST)
X-Received: by 2002:a17:902:784a:b0:1d7:67ed:f359 with SMTP id e10-20020a170902784a00b001d767edf359mr5047624pln.4.1706869008281;
        Fri, 02 Feb 2024 02:16:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706869008; cv=none;
        d=google.com; s=arc-20160816;
        b=ZRqN78G9GCn+K6pAnY4KqWIeFSGIHybha3/vApcEDqOteFvO2syA59SUHVtt14CBO/
         aw2Ymgd5eD0sU/I84fT4eG2pFK8ODino8vfQnB/pKrkLXpq6s7S0H74QMcDYVvQtRtGI
         3Xhuvolo7Fpy8CniVMgFUXD7L4ex0y/o4heohD1yCAUZ5w/X06yS2yr2yD8mHvde2TB7
         5ClMQGPYKYZzoPR/X6DomOj2B4j+4lXzhTu2aedUAWB7l0gwHfIJRIanrJJtWq47je2L
         sRmzTPJdxRZNQV3DWOkKtVPW8bgiP04PveOFqPzKznSx/5rHXwEdYjhS1VarIGL7k8ad
         f8Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=q2i1VCkuXMuVXp4gDavRJYrrSt5NKbgy/NVoBDThh0M=;
        fh=eyRomMevnGfV+k9Z4WqtinnVIN9Gt7ns4B1p4WqGEAk=;
        b=BQJGzMVlx91wLMmfEgsbvz5LH0MFuGu+Spd+ZTSiBN2DH3XB9fe/7Yez5pu+pmNosp
         0R2CP5wDhKrymbvO3GC2u6k51ePP0uH+u/mxyH2lluveeXREMD4YoR6CApA5CEQpAyKK
         O6+N/XX3fUHdN8MuHPT+MGvwTJAN+G5PidgOM+6KWA+7vCl4HLD1iW8SNamL+np54IMZ
         kbOzkDHtrllbVjtPCDdKj3C60q5+7HlZfSRccLF2/FU/zU8E9G4IrqsbuzlaeGFRrMYM
         PYUPJMi2V1WNEN1KKsZd6hEeZ+Iro4/zmTC64GO7ickoht+1yBIWrqIs6K97BWQXwxqR
         CPtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=fEYgpiAB;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=0; AJvYcCWisMAjw5tjEw2lPu/+uL+kBNOdlHKpfRGpo5QtgBZxBmMwAFMcodTMaGfLp8Xr/HPqILVvQP3ZLpmhLsRDUom49EDSHE7wvpPQ3Q==
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id g12-20020a170902e38c00b001d974ffa202si37146ple.8.2024.02.02.02.16.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Feb 2024 02:16:48 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-6ddc1fad6ddso1605086b3a.0
        for <kasan-dev@googlegroups.com>; Fri, 02 Feb 2024 02:16:48 -0800 (PST)
X-Received: by 2002:aa7:91ce:0:b0:6dd:dc11:8dc2 with SMTP id z14-20020aa791ce000000b006dddc118dc2mr4100538pfa.31.1706869007910;
        Fri, 02 Feb 2024 02:16:47 -0800 (PST)
X-Forwarded-Encrypted: i=0; AJvYcCUDF/5dB62m/sOjIqROZhnkW89FEkANVVRCSsiN/ECr+FkD/dgzhBxf+QOf9Bopcsha5T9PxAHFUDi3QZWoMBiC/pX77aRBJUfzZxheSKG9/0eOmFQCqXOQUzCEEdEhwbSw+zKV6uLqk3vdhPxP14K3DR9aELUUi6rQjbiBopkV4FYXxJEH8tuRgBjiPdjsYHIdSCXFLFdm8bItwabPBnLxcyhozafogQgFWE2oKxWm/bO97nDtoIdk8pJSEn5H5shYVIMLAw2Lo7psd/ru+eRDTxXxyJZOBMzd6eFuhmLEXFYJqFip7UWZt8IX9IKmnLy+s5GgNwfO6ixvMFckrJfpN2sTdxxiaHdMZQ5chuVmbyIVB9Ymkq/owWzUq9AvlOlI/lP7F7ONWYRCRYAIsGLehIvhVXP2kFvJhdDcOLxCq4KAXZxmu7WmJNDbW/lHEuHnhzHdgW80lkvnNGxDxduqiHvIWrq8VdIx+zae64TdojhtWt74NvdU/jiAutJBSj9XfXrzslGQ6hcf8iwp29Gp32w3/ZWL4bRSviEJaJ2boN/RxgS9W5wsHGvgWF4Iipq46c2DXvwUxpJyDHgV6lYB/RAQa4TRCTYLE0E=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id e13-20020aa7824d000000b006dff3ca9e26sm1239888pfn.102.2024.02.02.02.16.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Feb 2024 02:16:46 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: linux-hardening@vger.kernel.org
Cc: Kees Cook <keescook@chromium.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	linux-kbuild@vger.kernel.org,
	Fangrui Song <maskray@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Bill Wendling <morbo@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jonathan Corbet <corbet@lwn.net>,
	x86@kernel.org,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	linux-doc@vger.kernel.org,
	netdev@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-acpi@vger.kernel.org
Subject: [PATCH v2 5/6] ubsan: Split wrapping sanitizer Makefile rules
Date: Fri,  2 Feb 2024 02:16:38 -0800
Message-Id: <20240202101642.156588-5-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240202101311.it.893-kees@kernel.org>
References: <20240202101311.it.893-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2922; i=keescook@chromium.org;
 h=from:subject; bh=jK+D77ByRXO1IX7WwU8qUvR5ixL79v+nVqcsnlmg2d4=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBlvMEHcstMJILdukRJsh4gmujuHAUYtz++GFAVQ
 hi5nayK60OJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZbzBBwAKCRCJcvTf3G3A
 JowaEACziZiRMYcrf/X9h0kVApciR6BUA2ipAJztgKdBqXSmqSmN+Y6Mb6YdFdkhaeZXUGVuYtt
 6JibThi3e5zQSYGkwCG90aHZ/eoDTqApfT1HU538snWRN2mcmXHdCpXmZdVluThECFpOcYvyZyQ
 tWw6/AN9BsGeXsis0CO4wEdlk/n6BjoiRyi4g9X6IpD1Y4q0nJI+Cq2BlzpIBWdL2jOZ5JpQ9Nk
 DpgnFT3xUV/0Povx7yOkoC+ZEGCAOzJUfZ99G0kBxs0H3FwS90IH6U4hXYyN+ZANHRI/O4bsRjH
 VYaBIzURtbJdVzaK5UDpLoKaY+J8NtdBQWfldHf2YABl0wzsJjAL9Q3Fbg0Oom40WoNUVwa8QNF
 oL86NjJxmkhWR+j6NMy25VPdYgu9UHUWjB8VQ8+1kk0QZZbJioYe8aWYCyGbbq8KIwGKbaQ8f7R
 /GldqBleFNBG5HmKyGW4pfxBBInKcQb+SkFoavF5uzC3W+0U7f0xfPP3uJ/J6UTPAMORvuVoW8v
 XBgHMkiZm1kHFRDBB4HVC/ABM5/Hu3zHQOhOd3rMX5vJFZHEHWcjxC5viK/WZ/20O60lfOi7M5M
 hHYncOQDEHnVl92cC50LrnbUP29vgrq7u5RwdpAjzX2Wy1u8NGYLAIeGVG9B5QeiKKJtK1q1QGU tbcygIg9nEmuM8w==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=fEYgpiAB;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::435
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

To allow for fine-grained control of where the wrapping sanitizers can
be disabled, split them from the main UBSAN CFLAGS into their own set of
rules.

Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas@fjasle.eu>
Cc: linux-kbuild@vger.kernel.org
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 scripts/Makefile.lib   |  9 +++++++++
 scripts/Makefile.ubsan | 12 +++++++++---
 2 files changed, 18 insertions(+), 3 deletions(-)

diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
index 52efc520ae4f..5ce4f4e0bc61 100644
--- a/scripts/Makefile.lib
+++ b/scripts/Makefile.lib
@@ -177,6 +177,15 @@ ifeq ($(CONFIG_UBSAN),y)
 _c_flags += $(if $(patsubst n%,, \
 		$(UBSAN_SANITIZE_$(basetarget).o)$(UBSAN_SANITIZE)y), \
 		$(CFLAGS_UBSAN))
+_c_flags += $(if $(patsubst n%,, \
+		$(UBSAN_WRAP_SIGNED_$(basetarget).o)$(UBSAN_SANITIZE_$(basetarget).o)$(UBSAN_WRAP_SIGNED)$(UBSAN_SANITIZE)y), \
+		$(CFLAGS_UBSAN_WRAP_SIGNED))
+_c_flags += $(if $(patsubst n%,, \
+		$(UBSAN_WRAP_UNSIGNED_$(basetarget).o)$(UBSAN_SANITIZE_$(basetarget).o)$(UBSAN_WRAP_UNSIGNED)$(UBSAN_SANITIZE)y), \
+		$(CFLAGS_UBSAN_WRAP_UNSIGNED))
+_c_flags += $(if $(patsubst n%,, \
+		$(UBSAN_WRAP_POINTER_$(basetarget).o)$(UBSAN_SANITIZE_$(basetarget).o)$(UBSAN_WRAP_POINTER)$(UBSAN_SANITIZE)y), \
+		$(CFLAGS_UBSAN_WRAP_POINTER))
 endif
 
 ifeq ($(CONFIG_KCOV),y)
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index df4ccf063f67..6b1e65583d6f 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -8,11 +8,17 @@ ubsan-cflags-$(CONFIG_UBSAN_LOCAL_BOUNDS)	+= -fsanitize=local-bounds
 ubsan-cflags-$(CONFIG_UBSAN_SHIFT)		+= -fsanitize=shift
 ubsan-cflags-$(CONFIG_UBSAN_DIV_ZERO)		+= -fsanitize=integer-divide-by-zero
 ubsan-cflags-$(CONFIG_UBSAN_UNREACHABLE)	+= -fsanitize=unreachable
-ubsan-cflags-$(CONFIG_UBSAN_SIGNED_WRAP)	+= -fsanitize=signed-integer-overflow
-ubsan-cflags-$(CONFIG_UBSAN_UNSIGNED_WRAP)	+= -fsanitize=unsigned-integer-overflow
-ubsan-cflags-$(CONFIG_UBSAN_POINTER_WRAP)	+= -fsanitize=pointer-overflow
 ubsan-cflags-$(CONFIG_UBSAN_BOOL)		+= -fsanitize=bool
 ubsan-cflags-$(CONFIG_UBSAN_ENUM)		+= -fsanitize=enum
 ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined,-fsanitize-undefined-trap-on-error)
 
 export CFLAGS_UBSAN := $(ubsan-cflags-y)
+
+ubsan-wrap-signed-cflags-$(CONFIG_UBSAN_SIGNED_WRAP)     += -fsanitize=signed-integer-overflow
+export CFLAGS_UBSAN_WRAP_SIGNED := $(ubsan-wrap-signed-cflags-y)
+
+ubsan-wrap-unsigned-cflags-$(CONFIG_UBSAN_UNSIGNED_WRAP) += -fsanitize=unsigned-integer-overflow
+export CFLAGS_UBSAN_WRAP_UNSIGNED := $(ubsan-wrap-unsigned-cflags-y)
+
+ubsan-wrap-pointer-cflags-$(CONFIG_UBSAN_POINTER_WRAP)   += -fsanitize=pointer-overflow
+export CFLAGS_UBSAN_WRAP_POINTER := $(ubsan-wrap-pointer-cflags-y)
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240202101642.156588-5-keescook%40chromium.org.
