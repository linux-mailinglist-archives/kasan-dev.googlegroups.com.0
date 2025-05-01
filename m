Return-Path: <kasan-dev+bncBDCPL7WX3MKBBD5AZ7AAMGQEDRTF2OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id F005FAA643B
	for <lists+kasan-dev@lfdr.de>; Thu,  1 May 2025 21:48:32 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-e72ced90ffdsf1863406276.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 May 2025 12:48:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746128911; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vo47JY9PAy9vRq2V8B4uszhGathmefmsXEHqX3yKo/DyXdmgYDtGyzFKp9FUA0inrM
         2JPiDGrArJPT61FtyUSARz0RTq7ltuvtoO8eI2ko4rlS12C9S0Mld+GpQZn3hgXmNTYc
         ylv65sEHdy/nGRZ/5ZwFp9Ek50hLif6uZTeeU6fLSujvUku9yff8XOlsSRAEqEm+2qD2
         hXvxAgP8NzzvmUH9aa73DlCAnm1gb7swOILHNREuFYfXFtPydSSYoTm9MdYWyzzNVOsA
         rAKveKlEhxFTfK8aYtidQ1OAVMhpYHddJXPd3v0RYSETFioNsWCmFebl/kLE/HVL1VwA
         E1hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=1WUUjZlPlDxpymjmlyFMfUH2klKUp2FNWSECCim2GoU=;
        fh=Syrcp1f7aaaALUaqFW1zbXWNgTOjj75KtoGVXVSuEM8=;
        b=G9P+vKmnlyXr4Ivt2XxsN/H/Es9fW/x+zI7ehul4CK7BD+md/Jq2OjmNgMet6lgqqq
         U91QKo3rkWWMNZwy16PmI3C2uDeDUKnFl9Vv0UIxVneXA9ZSZ5Xh4jnTRlUmw2+P9JiX
         XI5drNZC9xvKcxVcZDHAtq9mpEuxjlsGiXF6lCw+QEOM36dWHXQvx3Nu5k4np/VFNkwy
         CAfwaHqviKuAfNncEuCc1fpauDT0cwT38r01dW9qP0XzXPLc++2CDFKXUigO4tjh/qLo
         UoUT1Vjh/xWjwKi+J/UT5olXKL+AHjG9sI747HEfKwKYdZEEmBhLaEz/XvPTpiqW+U71
         UB0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=k6XGbZ49;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746128911; x=1746733711; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1WUUjZlPlDxpymjmlyFMfUH2klKUp2FNWSECCim2GoU=;
        b=MYE+ebKNvfbYaI1zNEfKjPV6R+if6HKlIAxHL50VKyXoL37Ue2Dgwe9m9B1yuPRteh
         FJvPaNNqGk6zMcZ76QPU2lZ5zUm+kfyPyK7PekXrPFwnAN9wXScPIYgHKOPiGwsrZvxj
         V2RbGyhsxODCGJpBxULgu/oLLo8VCRZVue11GU+fxuTlJyoymi/Wvtg90IDw1C21h7uu
         /Y64qVuw/OxJcurDw1UGbUR2YS5ejJpyXMCEM8+lDHZgrSFFKpdLIBt/9vqCYo56kdtW
         K5eVPMWCdE9nEL8UP5chWPLXZJL92FF01suULCbTsh7DzhmjVlwQF1DHxNOP5OpXT8Es
         Esfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746128911; x=1746733711;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1WUUjZlPlDxpymjmlyFMfUH2klKUp2FNWSECCim2GoU=;
        b=bAYzJd/fpXAVgPoaAMKlmKxoUT+dfOL+G2jlUqPoG7MstaDbPCHoqKhU2Lfw+QzR6N
         iI6pK1/TrPkJEl6v29sn0zbQR3EO7DrNpqQUnEubenyis8tv9sQPOMt2gSwYipHW9jg4
         EiHaqRBaxofqkzdtYH7Q9ZbC/MnJ3pICgIQBEknHpdfmGJgWMEYFQfHRTz2lyveAmlKc
         WTbaW9PUK9H2wq75BFcmJpiG/UUL2ex2VCnESLuLDTS/K+rvpsKAogvjETWc7ni6Or6X
         7VZxvmd6J7s7P3WEb2CC1mH6THGtrfMtnCaex8HGsKEovxQeEtnICUcJhj5Wm9E5njbJ
         gc1w==
X-Forwarded-Encrypted: i=2; AJvYcCUpi1xjNcmqXZMkh8lQVF96fGWDU4B4/x+AxHg0vyPdAN/UWt6ql+9WILUVBsaXPN2GP9H7EA==@lfdr.de
X-Gm-Message-State: AOJu0Ywe6iT4Ps0rLi+ZJ4GR2CjH68KihbKVWtdUQNT9xK7viHzLWvVW
	GSoL11KsiqqZjLdTzFyPMHxh8jbyHlBWldHXahEJ/jpBTbdyBPW/
X-Google-Smtp-Source: AGHT+IETkKq0nbBjv+a8RgmcLIqVyJqgyISM71deLBgjx/9bdCy8uZYOZfLPI3r+vY2tTnpkrZygfg==
X-Received: by 2002:a05:6902:2209:b0:e74:cc80:7b8b with SMTP id 3f1490d57ef6-e75655326c7mr591869276.8.1746128911414;
        Thu, 01 May 2025 12:48:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEjyHQsVgB6/B6+lkSk/Q9Pc+GoadUNJyY00wMq4KM6vg==
Received: by 2002:a25:b18c:0:b0:e75:52b1:66fd with SMTP id 3f1490d57ef6-e7552b16818ls744207276.0.-pod-prod-06-us;
 Thu, 01 May 2025 12:48:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmM6OhwPDoolkHXN9jrvk3mYu1vH6+v8crddqfslF/2/tKXDrBMLeRTwhHCB31KdwEL1m5G9lW338=@googlegroups.com
X-Received: by 2002:a05:6902:124b:b0:e6d:d8e4:84c with SMTP id 3f1490d57ef6-e756553242fmr550677276.3.1746128910417;
        Thu, 01 May 2025 12:48:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746128910; cv=none;
        d=google.com; s=arc-20240605;
        b=Ocgyr+SrNSRodPe4xyhheooAkFfz8Q2YqMfR6NvE6Jk0wHjJEIbE2+37vsunakUHt0
         s6k09VaA9PeQRtjvhMm27sc+fz8f4RmHyov391g390At9jgP8Vdd6c3vbPfXZhBL637n
         nsOq1Frl3AszKVmdWSbWRRIRtDGjBx9WRb55+8d+0zaYHa0tqz7vQeKtJneR2G8i78mw
         WN5LmIcCiaax2TABoyC+ttFBPy0Y+XgcqtH/I3QbLgfQxRrtEb7rKc++CkbUWztq0Afp
         XpoKfXRxUc+G+HAzojSe9CBsRO/kkKmzbX3Gt61u+EFcvBT/A1+HQG6RQmDFh3AFFFY6
         mVYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FFK2DOZEf6AqtDzS98qdCq9UqWcfOQNWacM/iJX6uCc=;
        fh=1pjrXVL6Y5H7GjcUzACxutq8u0hLJTSULHEr9ZYbFHA=;
        b=Yn1U30PyW85TJ92fE/TWIm9pf/WLvK2KjEL5T7y+zNcFTvnRBxTH97uNOwk/bVBIEo
         8l+w2GtgoDsl44NdVx5Eizh4Ld9BctwQCbOSX95n/ehS0kzgvAQ9Ea7Gecgz4hG58M1U
         N6s9Mf7KdabZrOkUte+h1nWSlqfy0xkUb43u038XfSmeF/Ifj0cPK2mZf7wY8//YlLQP
         sCj08DLBIhoAUL5btUg48zJ51X2VwOrTUf0AQEAcX6/o+PMD1T+qCno/irtMxA7fc1Mz
         k3ZrX+digHap84ATDJZpL8BiShFf9C2cCifECMVohkSfIo7qpn4156C34Dh0A1254gPY
         SzSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=k6XGbZ49;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e755e6e6d4csi58415276.1.2025.05.01.12.48.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 May 2025 12:48:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id CD1AB68463;
	Thu,  1 May 2025 19:48:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1AACFC4AF0B;
	Thu,  1 May 2025 19:48:29 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Kees Cook <kees@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	Petr Pavlu <petr.pavlu@suse.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Justin Stitt <justinstitt@google.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH 1/3] gcc-plugins: Force full rebuild when plugins change
Date: Thu,  1 May 2025 12:48:16 -0700
Message-Id: <20250501194826.2947101-1-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250501193839.work.525-kees@kernel.org>
References: <20250501193839.work.525-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1929; i=kees@kernel.org; h=from:subject; bh=nJ/O2qfc5y7+GRelzxRyWAg1TE/6pK01eAAImGz7s0o=; b=owGbwMvMwCVmps19z/KJym7G02pJDBnCFxh7neu0XGZnlWzRUTPY0/hmqavW0X8s8ZvqWDaLM YtfZWDpKGVhEONikBVTZAmyc49z8XjbHu4+VxFmDisTyBAGLk4BmIixGsP/0Jsy0+XCkiRaDyZ8 a3qewybydodJZSCjU7gao1DsHN1sRobLb+7dut0Q9Cbs45z/D6p6V370npSh9UJGkSmOZXWL1E4 WAA==
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=k6XGbZ49;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

There was no dependency between the plugins changing and the rest of the
kernel being built. Enforce this by including a synthetic header file
when using plugins, that is regenerated any time the plugins are built.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas.schier@linux.dev>
Cc: <linux-hardening@vger.kernel.org>
Cc: <linux-kbuild@vger.kernel.org>
---
 scripts/Makefile.gcc-plugins | 2 +-
 scripts/gcc-plugins/Makefile | 8 ++++++++
 2 files changed, 9 insertions(+), 1 deletion(-)

diff --git a/scripts/Makefile.gcc-plugins b/scripts/Makefile.gcc-plugins
index 5b8a8378ca8a..b0d2b9ccf42c 100644
--- a/scripts/Makefile.gcc-plugins
+++ b/scripts/Makefile.gcc-plugins
@@ -38,7 +38,7 @@ export DISABLE_STACKLEAK_PLUGIN
 
 # All the plugin CFLAGS are collected here in case a build target needs to
 # filter them out of the KBUILD_CFLAGS.
-GCC_PLUGINS_CFLAGS := $(strip $(addprefix -fplugin=$(objtree)/scripts/gcc-plugins/, $(gcc-plugin-y)) $(gcc-plugin-cflags-y))
+GCC_PLUGINS_CFLAGS := $(strip $(addprefix -fplugin=$(objtree)/scripts/gcc-plugins/, $(gcc-plugin-y)) $(gcc-plugin-cflags-y)) -include $(objtree)/scripts/gcc-plugins/deps.h
 export GCC_PLUGINS_CFLAGS
 
 # Add the flags to the build!
diff --git a/scripts/gcc-plugins/Makefile b/scripts/gcc-plugins/Makefile
index 320afd3cf8e8..38fd4c9f9b98 100644
--- a/scripts/gcc-plugins/Makefile
+++ b/scripts/gcc-plugins/Makefile
@@ -66,3 +66,11 @@ quiet_cmd_plugin_cxx_o_c = HOSTCXX $@
 
 $(plugin-objs): $(obj)/%.o: $(src)/%.c FORCE
 	$(call if_changed_dep,plugin_cxx_o_c)
+
+quiet_cmd_gcc_plugins_updated = UPDATE  $@
+      cmd_gcc_plugins_updated = echo '/* $^ */' > $(obj)/deps.h
+
+$(obj)/deps.h: $(plugin-single) $(plugin-multi) FORCE
+	$(call if_changed,gcc_plugins_updated)
+
+always-y += deps.h
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250501194826.2947101-1-kees%40kernel.org.
