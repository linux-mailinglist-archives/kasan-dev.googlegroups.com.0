Return-Path: <kasan-dev+bncBDP53XW3ZQCBBAO7WXDAMGQE4HXKX5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 25F1EB8A203
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 16:58:11 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-57893a7d857sf2473373e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 07:58:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758293890; cv=pass;
        d=google.com; s=arc-20240605;
        b=CcXAdtzXJoHjpLBEB2tLxITKj/uZuqBYoK3XuvdNvDc7FY1lJVG1TsYEeMEoorwdSC
         r8hY4SYJds/YM+OHtpIb9geb3USuFZKzhqUZK/pyWIwVIaVwRgq1VM8ECxteGR5yv79Z
         XEseg+ibkY4KVBO66Qvpe/vz9iNypiXavzZx5KvbaxSql6Xt99sF+9L7ZvhvpgysI1Hl
         mLGUBQk3CBKUGqJlmtf00qadG8Z90XjGQYt3sviaGp3WbfOzXokc30/nK1piFJwHdijZ
         FtTVsyGq6uD+cG1jmkSAnxKP8Ro/rAeEpupz9SspuUA6sfz1CBSpZ+fD+v9TXcAt9ZlA
         kq1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=3mZaphQEBZWnDyhImnc3+euml9KdNW/ruBR+0BPk/Uo=;
        fh=9R+x0CgICA4o/iuYEs6acQUq4NT7jJSpPLF5sRTVa/Y=;
        b=R7XXIAhIi9NAp6xpgbgs0Svy5BgxG4Q0jOxhiah8wmbDgpXr+om9myPkiAWqh+nx4C
         8eoTRV76lF3/nwGWA6lUw0hiNylkgRhhfgQK5I6qR+48KB1ifK1adfwXb8fOgjN8uD2d
         T9PpnIKpyb4Q/nnAVd92ifsknNNWOxBdIHoEWnWX3c3i2lbqqNroFL3tOki25kwl4f6T
         xG8giAzZU9c/Eh0iId+WKdAaGyJdbT4P8Z/sPd81bndUksuOYjsw/Q57DcFWQWNeM9Uh
         aacxk23sRT3aB6v2NkUI6xiUPgPcSx+f7xCzYIYvBzF3Qvy1uEHUUfigrP0XJhSaOcty
         22VQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UdnlQP30;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758293890; x=1758898690; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3mZaphQEBZWnDyhImnc3+euml9KdNW/ruBR+0BPk/Uo=;
        b=mdTozGo2oBhCwwpX97zMqCrSGGYbBOF1DBztUKKFHV8R4TTN7ZPIaM7lyBOXLSBS5K
         /AFsSHeLEUrNp6eQoDelFkeUfk7qwbyajGpennHKUHWAJX0W4/gbHr4Mr1AIGNOGbrKD
         8SMQ704yx254AdQN1QQQtl9/36YFd4fYXTHYNTJxt/dpS/xlSKxgUnCWvDoxhtPjCIC7
         YtKAM+oWYSRYx9hPyu+YERkYfjUy6d9Jc9rTt2BsfGUzF7x/mstGFgTAdVA3eRcHRZGw
         qLddZDdyZSo17kcO3V6dib9JxEf+V0gWdq9FF+IZiYdNPAcGTeNnYCHUMdsxnxG55QVB
         Fdiw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758293890; x=1758898690; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=3mZaphQEBZWnDyhImnc3+euml9KdNW/ruBR+0BPk/Uo=;
        b=ilFoyjGfOHAEV/gwv/GRycUMPZpljSrOdK5Mld6L3gAhLUZVz7HmPT4nwXgBFaRqCA
         DJo3bZltApumIcP3I2KiLKlTuuqVY+0pgOloZMPEt2Egp7p187bK3+f9/WXy1S4nIeo2
         Mbzlxm+VMU1YjCUq9gSRbtM8mahFszXK1chgVxJv6DzIkfs39Imb4DRX9yzaFdabYbgN
         DxXH8ODDJSyNLNBsrJ4apQ6Z5r34q5Ii6GCr3ZBnrns1ac+7DIfK11RXCUzGfeILn9p6
         gieyn9BoTI8abipDC9q8bwudWqcHVx9wooD73J3rQDicScZnfRC1tteL5+VQN236swFq
         pKbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758293890; x=1758898690;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3mZaphQEBZWnDyhImnc3+euml9KdNW/ruBR+0BPk/Uo=;
        b=lGHBg7csYopLPmkjbRoRq3fHkp3boAWutdc7hUhswBjpHkAq+OpTRwEABOjL8O49oj
         D5Bp7ok3/H2F+Q41czgoTeXIn8wztVzPPcW9hlNX05RJPCs9CgpkD9ykU66iZnq57sQv
         kRn8Gjv933YHADvAWhjMrulE43MxAGQJB9x5qeq4NtH7ANGbLU8LtApsq22UVJoFZCGg
         /NpJo8msPde1cW6Jf7A32tEq3vFablMWQiNX5gaARryrbYgAh5Y7Tc0V9OEPVmfjtv1m
         qPK0yTgJ2bdQ6+evScD9E4iT9WnFNNgRoFmWBd2lCgDrpaXQmuITGFhDoVLysA23/6G1
         RqJA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV6CQ3QIvd+rW9dpeepr5SZDNA/a/6dHQjhg38rYrZhOxN5JgwdemTJ7+jAZgDkBWMtZFKgaQ==@lfdr.de
X-Gm-Message-State: AOJu0YwIDVqUVV2uIAyWerQZLfujTTwXHQN5nIxBchvtFwqM9tQzMROH
	hQf3y9eoZe41JthMEYec+cqmOmKTpKJSF8smFUlwU2tB7YxbDmyCXmMl
X-Google-Smtp-Source: AGHT+IGh8jfpTr6MlIlPsyM2tgjnoeL1OsN5wDnDzRYLj7JpjNaJdZMQnxBsU6izDtslTglR/9OU2g==
X-Received: by 2002:a05:6512:608f:b0:574:7258:26c0 with SMTP id 2adb3069b0e04-579dfed4c20mr1449591e87.17.1758293890135;
        Fri, 19 Sep 2025 07:58:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd59v+xoVDDsdIHMm++qf7/y5Zh4OLjw24jDVC27Fpav5Q==
Received: by 2002:a05:6512:3e3:b0:55f:48d5:14b3 with SMTP id
 2adb3069b0e04-578caac3307ls645905e87.2.-pod-prod-05-eu; Fri, 19 Sep 2025
 07:58:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXsMAMPCAm12Tz5ija4KCwjbI+LW4WjvVibB3GXX/UDdOChs0RABDllpNmKkeCdaG7uRtpPXRPdpsA=@googlegroups.com
X-Received: by 2002:a05:6512:2093:b0:55f:595f:9a31 with SMTP id 2adb3069b0e04-579e25fc67fmr1203498e87.51.1758293887240;
        Fri, 19 Sep 2025 07:58:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758293887; cv=none;
        d=google.com; s=arc-20240605;
        b=CvhdxcU++/2kZAYK2UcmpYX9AjGUxhlRLOeJ3CmGPO0W+eHJpC+8bYgjTKXQBvrEKn
         GvMHsV0MYB2xB5hm7wBYnLNN/nfmCXlmyrDNCjH8lVxaRJA2GZFu1N/nCBRUAzF9SvHl
         hiXOwIqwFJm5zM8O+5gAdrYTWtOJADmk1Fp/76arTWQE4LGKcqlPFJXmHZba/Z5POyg2
         YwqOrrX5+INDgwjv+MF77E8nanw6Z5fGgFAbxA8qtb6U3HOVhf0k+K34sMnjAFhXVydT
         Ft1CsVOmesB33tqDQAfJpnkaWrcZgcKh/BK4dIECAkXFlVChDtg3vJoKUIc5NrmTqkhE
         gkJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=cqsEMj50XfHOshwHI2kqebsGSz4e9jnLx3tuTedHdO8=;
        fh=uLiOV0pbwuO1MnQ5EN0HNrjH87/B6IgzZJRR5FGtChs=;
        b=k7II1e88WPyjYjov7jmB18FxaSiHmm0W7bkiktjGzn9UMU8kwUYYdQnHMadgCgFcQQ
         PAAyYdF5ycvQ2M5ghl83gqALoZ+mSDQLdgwGF9FYh6MYnG+1cwDp30nUtRM9EUzf57yf
         778Hk/A0JTs1lO56Ox5OH1ElO6Zwfefm3Fol0zFPorHeVuDe5l7Cuh/SdtxVpq9Aqk68
         /PqLbt1CzF+SrLDzgZumZQvHhajCvHKl9qZdq708ZBPhVmN+ObdvJOltWIwysSOloAz1
         UOuy2LzRmfFk8snu5W6p2jkSBIuPRgvnJbmSNREMvu/T5GkROJsFB/+RQhXgTpZ25O/e
         ulrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UdnlQP30;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-579c296c668si67825e87.6.2025.09.19.07.58.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 07:58:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-3f2ae6fadb4so72793f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 07:58:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXLQD1O8cW6wd/afAFtKQs8RyT8Gn0pWotEZV1xJecgIlpXoK4RtllLfjObEeG/CVuQleJopSUALSo=@googlegroups.com
X-Gm-Gg: ASbGncuBqWBYuxsI2LTuK+vXygLvfN6A/yWXUoRDwOQQc8TcyhUQqGNeYdg/hnfVTzl
	NfASwrwt2wv2fO0AEi7QuYvp8JB2iDI2gy61mSU1rsvf2OXhJlTl6dtrgC2XNIF//5M6zTknw4W
	i8nB+KWib/EDSNpr93w8dVDb4PsrBUgHsNDw4kbUN9lRWLJMHBPGMopcWbblVcR4q6mq5QNYNu7
	87nseNdJm31jCDQnfX4skj5B86r4wjD+AuW1Cn2zZVckpZlqQBpKn7ZK9SdUhZ+Nglholpc5iJf
	hbQJL/mbE4wpg27JHtJL6qJhBEad9KzHgh5OihxJ4aumrApaKmq+CsbUzahjxS8L9GAfOPyHMZe
	6OsVA/wYCqEestZ6KEsoZUSfcyTouhbJvzvwvIgYWUefrA9fDq4MC3AA58vFC2S9Br45Qyq84bY
	6wXouj5YC/xm/eFZA=
X-Received: by 2002:a5d:584f:0:b0:3d1:61f0:d26c with SMTP id ffacd0b85a97d-3ee862edc77mr2891484f8f.54.1758293886534;
        Fri, 19 Sep 2025 07:58:06 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (124.62.78.34.bc.googleusercontent.com. [34.78.62.124])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3ee0fbc7188sm8551386f8f.37.2025.09.19.07.58.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Sep 2025 07:58:06 -0700 (PDT)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethangraham@google.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	andy@kernel.org,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	elver@google.com,
	herbert@gondor.apana.org.au,
	ignat@cloudflare.com,
	jack@suse.cz,
	jannh@google.com,
	johannes@sipsolutions.net,
	kasan-dev@googlegroups.com,
	kees@kernel.org,
	kunit-dev@googlegroups.com,
	linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	lukas@wunner.de,
	rmoar@google.com,
	shuah@kernel.org,
	sj@kernel.org,
	tarasmadan@google.com
Subject: [PATCH v2 10/10] MAINTAINERS: add maintainer information for KFuzzTest
Date: Fri, 19 Sep 2025 14:57:50 +0000
Message-ID: <20250919145750.3448393-11-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.470.ga7dc726c21-goog
In-Reply-To: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UdnlQP30;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

From: Ethan Graham <ethangraham@google.com>

Add myself as maintainer and Alexander Potapenko as reviewer for
KFuzzTest.

Signed-off-by: Ethan Graham <ethangraham@google.com>
Acked-by: Alexander Potapenko <glider@google.com>
---
 MAINTAINERS | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 6dcfbd11efef..14972e3e9d6a 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13641,6 +13641,14 @@ F:	include/linux/kfifo.h
 F:	lib/kfifo.c
 F:	samples/kfifo/
 
+KFUZZTEST
+M:  Ethan Graham <ethan.w.s.graham@gmail.com>
+R:  Alexander Potapenko <glider@google.com>
+F:  include/linux/kfuzztest.h
+F:  lib/kfuzztest/
+F:  Documentation/dev-tools/kfuzztest.rst
+F:  tools/kfuzztest-bridge/
+
 KGDB / KDB /debug_core
 M:	Jason Wessel <jason.wessel@windriver.com>
 M:	Daniel Thompson <danielt@kernel.org>
-- 
2.51.0.470.ga7dc726c21-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250919145750.3448393-11-ethan.w.s.graham%40gmail.com.
