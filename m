Return-Path: <kasan-dev+bncBCF5XGNWYQBRBV7LR6ZAMGQEIJVV2YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C8218C5E1D
	for <lists+kasan-dev@lfdr.de>; Wed, 15 May 2024 01:38:02 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-5d8bff2b792sf5607122a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 May 2024 16:38:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715729880; cv=pass;
        d=google.com; s=arc-20160816;
        b=JtXlDTltPPsTydOoKAynB5JaDN5aKFGcO3tIDTNQ1hFsF/tAzHtSGPLBG8aUQbG0+s
         cI6OWJzr6q3L71J+REBubcRbSr9/MVAD8DGpHrOxvB1/JlMJyHS+m+3MXg8SiOJN4BJK
         sWy1TIUAw+HKVaA+zF8+ugSo+eiTVh/WUX5KQbifJ7MX+pMJgQa43YpQ6k+sC349puYL
         1pMgVkJctHLkMa7cjAkj8BJNbHJxJK63vmpThFFXkr6eeBMGHkQHcguGD+iHmDKJ1ffQ
         Iopegl3aLYjfBpb4xt2eloQqPTZXput8G1yNB9cmJfH7ZPIUasgSiD+0ejj+p6gcsImT
         P0Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=bpvsg8/Y4hu3S2i6fUbddX33pgl40XTNrVrNAOEG5zw=;
        fh=BVm1+Ewp8Dkgqh3Jq2Tqxza+W4bEsycyS0VbyCZt7js=;
        b=CwmvXhD1spV1GLXVP7EG8jfhWxCa29qljITme+01eDhj48xav6n/Rb92PIbjRLVXJj
         +Gg9oqGiY09Xgbz1smhvUXlBDig6803ekxaM81bj8hhwsdzVCoDSkzjaNsIqvq7BluUb
         Ae35+zxoZQbW9wiBOIrVSppH16cVlRkKJ15oPILfkPsUy6IzoLGZa/HDfcypcevixJfd
         PjpYjjgiC6rBR5/2/Caa40HCFwCr+5G9k755yKSgO/YPA0tPQ43ycwpCZhhwHauzhJfB
         CWlDQJn79SayIfL1fe46xoFlirhibcTcBZ6R++S5/2S36VSZTJPe/jATjKeUGIgtoMVn
         T2Pg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=TudvSZWo;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715729880; x=1716334680; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bpvsg8/Y4hu3S2i6fUbddX33pgl40XTNrVrNAOEG5zw=;
        b=ixCPtno+uq7Y/8bysMyfZwNgEouQlv5pSxjw9Y1IXzrgl5JwVszonRNWkHxXhbo7rw
         apmlIlSZVTUh1v/MMoIgBEZbkVITX4/O0rgUVoUvS3zky0U8SI/DOBebsNXW3tzr9eHR
         /isycND4qDsz/eaU97gC3/6C588q+Gd1QMfaVGvQYYPDiv8kqp0NUMsBti7pXTJ5nTw0
         DVvtCSsWACX3QmVdbeRQIPWdIPzMIQZ7GehSwH3G8GZCl7dA5od6NI6vHQ6e/FKgjkBt
         hLcN+2qTpa+Qwo2hWl/86zGew2EPhFnyR6GF5Beaw+J77c7lpz8VX17IrI2stjVuUKmb
         BzeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715729880; x=1716334680;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bpvsg8/Y4hu3S2i6fUbddX33pgl40XTNrVrNAOEG5zw=;
        b=B+bbnllvb7bd4ybXV1fFz6g6Odo40B+TRfHqx74MhSUbf3/nV809UeIu0KhipcTCFh
         u+uRBzRliFCKn6ZUbnBEaeWjtVNhdio0aAao5KnA+ZKBK+DK+MUC6ZCBpaet9uI4ub2x
         mxgxIiyGGXQBFuhRiCt+InR7mUY+oUnfKsLCGD8t8rAh4+gnUJjKC+2JugnFzidNqCk+
         HpDZnDL5+cjYc7bn+7Sj8ke6dFX9GvbJULbAR3v6ZNAdOcQsGscaHlBO5kfcgOAxhDu4
         Vh2dknx/gDPsEjY5yWlpXEUKf36ZOXcyrfBFeftcfZsu24tvCPkwJ7FdDF2uC1Xv9GoY
         wo3A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVmFDFn3mvJqtx3MYgGkgeNjUnWaFsL/VzjhNpKuANtc50RT2+tRH+dL/f32rVDSKKX9jhKWY8Mc8VcBO+PUKKdHF67HfB3TQ==
X-Gm-Message-State: AOJu0YzSfnG3jx5M1X9M/e964IGZAIi1OEeAybcM+QSMWNDe/uQKSKvn
	QZffDbWHKG0+5bid6mFzxq9pSFDGvyrUvIpvWEPJwdRBZeAL2VS4
X-Google-Smtp-Source: AGHT+IF0ZakrSkfpcxWx5Bugr1FDtyjvhL9u6iz3z4Xvan62E/2zl1QE6UTIUaDRmqAdi3IB3iErYg==
X-Received: by 2002:a05:6a20:9498:b0:1af:c5b9:273b with SMTP id adf61e73a8af0-1afde1d824cmr14005940637.54.1715729879745;
        Tue, 14 May 2024 16:37:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:6c86:b0:6ea:967c:6a02 with SMTP id
 d2e1a72fcca58-6f4cb775903ls1785533b3a.1.-pod-prod-06-us; Tue, 14 May 2024
 16:37:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUtu9IX6mkXjCVXr4iZQ+LXZc+AatBDka2CSS4ZNllFWyI8WQwLGgkOcaWIG7XAua9dKBcJ9y63d73OFFE88VHlEICxtKU6sUnIfA==
X-Received: by 2002:a05:6a00:2444:b0:6e6:f9b6:4b1a with SMTP id d2e1a72fcca58-6f4e02aace1mr18143090b3a.11.1715729878494;
        Tue, 14 May 2024 16:37:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715729878; cv=none;
        d=google.com; s=arc-20160816;
        b=CgTfyyhM/QMJC91ti2Roa8Od8RRSZCmYc3gLRDmI/UsIViqK9K50gH5cn+jP0JzjPF
         uFX64oua5GAUD5rIUOJ4XbUfvxD5mdkeNGZKxIiVC3bjBBPJwmnZdCdTcAqWAvYCrG4K
         7uboditJSPLYPIwvdLBFcNzgMo6Rc2YPXMpf5YtdcUgco+7txfwaWX1cxqAJ81i6WT3t
         DyJRlelotU39p3d8+CEkYMeRT5i79NakvTfU0GVMEvvLdaeEJvJ71mY/f/QFXUqenXfu
         7fAKXyAPDu5iqoH4ifY2Viq0mQ/pCtcIEJsZJI/qgTJH52whHuxreXaAJdTka4cTntH+
         qKmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=U/46gzPRjfsjywIh4JZDG9x4PubRXzjsJhZrxZRHzS8=;
        fh=lJ7wVuNM18dxcVoYHYpCJn6Da9SBY+yS+RhYFx00QtM=;
        b=mP4pkItABRxcuzbWNbDAjBs3XsgUwsyW97luSf9qUZuz6zVLOuzx6DoqPLrK6wB9eO
         rhZVECQmnLgXGidqgJcPG1Vtk8WjFhJ+1V+Em52x44Lhw74pglLWBE7ersRUFXFoskE7
         vNYy+Dl+XXkSmICcPcDt8AqdMKI9NVSAHL1qwC34UMXQdGem9DS6jq6+WaQWkERVaaq0
         xTPc+awYGA+ghMKkrFaxdVgp5EW/yS8MRxGufCeoSF1zZZ5rDBUTfs8dYEDGRw+lxU5u
         sRR0SjwHQt21g6y9TvmO87XIdHwS2oKpHELpCuTgWt3A+xUmF+YO1kBiAquVQa6S+zBr
         sD5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=TudvSZWo;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-634024a452bsi869300a12.0.2024.05.14.16.37.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 May 2024 16:37:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id d2e1a72fcca58-6f5053dc057so2683596b3a.2
        for <kasan-dev@googlegroups.com>; Tue, 14 May 2024 16:37:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUXPx4tXTu7ZXpZ9FPrAwC3KRXK97Stjhg7vD4TWvbwPDtF6ecu7du9UAaoNw57NzMpO94JcIxGd/EMUbIMANWmHLpozeAgoJQ7cA==
X-Received: by 2002:a05:6a20:9782:b0:1af:ab0b:1c08 with SMTP id adf61e73a8af0-1afde1b6f80mr14140701637.46.1715729878103;
        Tue, 14 May 2024 16:37:58 -0700 (PDT)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-6340b76e262sm8858679a12.35.2024.05.14.16.37.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 May 2024 16:37:57 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] ubsan: Restore dependency on ARCH_HAS_UBSAN
Date: Tue, 14 May 2024 16:37:48 -0700
Message-Id: <20240514233747.work.441-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=1157; i=keescook@chromium.org;
 h=from:subject:message-id; bh=M0ojsRsGu00hlS+3D/N7mtRoW2fXDtGb0dL7Dj9nSEI=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBmQ/XL0cMiBAzkKwdeLzy9N0TrgLVfExeGQZ0JN
 BHF7seFPsyJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZkP1ywAKCRCJcvTf3G3A
 JgcVD/wOawyFjlRnf29/qod98RqXmvKGYR/z9gCakCBi8CxR4/Svp5cc0T+1pQzJxoBBpejCMg0
 pxH/ab2G44oXnSULaNGapGZ9ntp42d7DnWiaGdghDJs4jq3mBvhU0185EFH6k8FjNeio8qOlkzv
 LB+qmxeol6rTzNUICQEJtpC7MjGXDrI/JUqDk1fZv6ff4wyQo98trBnhME4QDzoTGzodcr85+MK
 seSwVJg6ecBebIIFhz3DVVzIJnNxeMxEnZpTEssJLlImhYpeycEbBFSR2zDyTvse/FGdwy0pUFK
 QM4cI+mh8yFa/+zN3C68no7tg2X4sBU9dMnRmQbj9mASW8Sb0QSnWVxY3v+5RlMTtESHi/17hNW
 rrv7je0gK4u7WSLM2ayMhcVuGBo6QNx23Jl4PnB/3ONTkgDdcPszSp0ZPMC+ZxifMJF1myji/kE
 JhrrIhEKljsD6Di1P0ATy6w3ZgKnqu0lFKIGkOetXWIFTOYefwC1q4MH7b3xDklAqAlIsBvEaR7
 1aQCDkbTy/0YQCvK0n2IUMBrFXZR3VYLlbk9MzllZAeApJm3Hv9Kw1O7MDrj9bViSqrlzXNA2H7
 OBDGcCh6D4DMvDBgFJO4rmlnrgsvq0AgWoOTzGdS8A0pH9fGFC06u3z1Jj9A2K/lntAbCWi1qKp
 9P8N+ld MNH39rig==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=TudvSZWo;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42d
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

While removing CONFIG_UBSAN_SANITIZE_ALL, ARCH_HAS_UBSAN wasn't correctly
depended on. Restore this, as we do not want to attempt UBSAN builds
unless it's actually been tested on a given architecture.

Reported-by: Masahiro Yamada <masahiroy@kernel.org>
Closes: https://lore.kernel.org/all/20240514095427.541201-1-masahiroy@kernel.org
Fixes: 918327e9b7ff ("ubsan: Remove CONFIG_UBSAN_SANITIZE_ALL")
Signed-off-by: Kees Cook <keescook@chromium.org>
---
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-hardening@vger.kernel.org
---
 lib/Kconfig.ubsan | 1 +
 1 file changed, 1 insertion(+)

diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index e81e1ac4a919..bdda600f8dfb 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -4,6 +4,7 @@ config ARCH_HAS_UBSAN
 
 menuconfig UBSAN
 	bool "Undefined behaviour sanity checker"
+	depends on ARCH_HAS_UBSAN
 	help
 	  This option enables the Undefined Behaviour sanity checker.
 	  Compile-time instrumentation is used to detect various undefined
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240514233747.work.441-kees%40kernel.org.
