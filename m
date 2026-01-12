Return-Path: <kasan-dev+bncBAABBDG6STFQMGQECBLPPXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id C9848D14593
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 18:27:41 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-64d1a0f7206sf7094933a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 09:27:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768238861; cv=pass;
        d=google.com; s=arc-20240605;
        b=eJoUjtjN2u9goTg9B1T4mxrPMwEy4j4tEKjhQX45r9erYwjGRxmFhrjBnCTGrHnTSx
         Wec2nvCWaiUAfH7+QSJlJXddUb2yYdCcW5hGBlkDYQOLVZHBGMpXFKg0uMF7YpH9w7ro
         V8kt717bjPZbOh2shqD8R9IlvaCh+eS50hYEsfAYevZlTNvSYbZ4meqRp9Sgc/NOOaTf
         TnUhVs+1qJZhu03r9vGKLRQS67+R3h+FUxYoCmxNz4m01hPhsizqhdrOAkg552i3xAGl
         v/53Hw1BLLz1MD4WZpKmw6VrfwFe6ekuuz89SaKsD1v61dN6j4l4NHY0tkoE4Bobi/HT
         tzxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=iktyaDAx4XXRlGPPK3Qs6Rl4WGkCxkTCLdROLHeLUS4=;
        fh=E0X4DEqp27ehcXkkl06rcl7nxmF0W/ZFk8IVoLwIX4c=;
        b=Ng1bjy/w4DIcjFF1GRvoTHrsW73iG3m6BHCZrjL22AypJVnPCiipyC4fD/+c46U7kK
         luxHCmVRTTXPm9Xnz3/sMb1ATKI2KpgSIaC/Z/8O6dnldV2HjO+lV1IlXHKgnUexUMV1
         9g7S/QE4h5a9kqDnFSM6AXaoGr9RxaQBoaZKa10Ly5kmRjKWkl1kHbh3rs54AzsijKft
         03Bt87LHxqTH9h3eaIWeB3xpGxq0kgkKs8CdCbEN1Bsp4PS2dpzQPmQY7JnSU+0+bGcI
         7k5w243pI9lxZ5BB/K42uiJAGsVYvDiBA2bwxrPwqLUpmsQoryiyscdI9XXiir4PyzVl
         HsXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=rp7WD2hz;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.101 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768238861; x=1768843661; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=iktyaDAx4XXRlGPPK3Qs6Rl4WGkCxkTCLdROLHeLUS4=;
        b=IOWWHe4Qy4SK+fZ6ACUVmVXSrgl4f5BZnTfMy44pORwkSS8YRyt/31a6obRdXKN7Xz
         O7z5WtujkSwAqFnDexqyioSsMp/wQjdd+sfANZT95TPYm3xXOJ5d5KnhynAUe3/ZBKai
         Q5YbvIsYTQV73W4X/pgnWa7tx8hJtg9zbRrAjbRCh5pSjzo6s9Xxy5wIbhZ2rxCPak5/
         DDh1LeJa3W7mJIw/NKmRfuRVCVv6OrHd/ls8TwJ6HjpopBQvJoThScRg15whcnBPXiZU
         Jk9cEQ5jsiuE32FgfOoxP1oG279D27NnuOKccJNcJjoXmt4dZ+N0LDlsx52zcGysEgio
         2gLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768238861; x=1768843661;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iktyaDAx4XXRlGPPK3Qs6Rl4WGkCxkTCLdROLHeLUS4=;
        b=khAAhMT4phpygLyW1QamjoOQSMHulSaKBAg0RQ6yMvAP0+cyNARgaOYHFi4FybBPY0
         6YeppYeQCer5hcKOANdiRwEvE3/F+qxPojJN0DDIqUwQ3g6YwcB43w+swpCYeuTuSx44
         jXJg7vTeCwZGWmbw6gnM/w/ZEvfH3DLYfAn6ZkJlREiJVcraIFDJPmM3BlM3sLEJQ2xY
         275ZL00modXy7dRQrOLgxYDMvDzd6ElroZX48xPvKmeeSAeueWgPuEyTS1C5VubwveSL
         e59w5nvbMR387q6Iv25/1QmWW9n/msive3t3fWnYo3hVO96QzxKDo9T/UuIsJPlcJ3Ut
         H9ig==
X-Forwarded-Encrypted: i=2; AJvYcCV4Qk4IAU3V/ih3JzGOvHoJm+sYoFctAMT0dMBSe0xXeV1Y+er+HrWFmK92V0iX8cUAcR9g7A==@lfdr.de
X-Gm-Message-State: AOJu0YyoYCa0fSXVXirGtZqI3bdDxrAg4W5oxLp0KxPvWMP3JvlYZCYy
	LVvAAhaAeCyPnJORrPmMBiwUffFkE87HRBI8C8tfljW1xXKfVTZlaVjS
X-Google-Smtp-Source: AGHT+IFG+qLeSabKPZUQ0cq2kSkPoYZ0tbRPPsT1Cl73AGhjUYrAgpF9mv5SYe12BRz4D9iIBLImng==
X-Received: by 2002:a05:6402:5245:b0:64f:cfa0:900a with SMTP id 4fb4d7f45d1cf-65097dcdd13mr16011087a12.1.1768238861289;
        Mon, 12 Jan 2026 09:27:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FG6HNfvXPpbO1CiR/geIAT5IYXew9lmoG95Pg5NUALhQ=="
Received: by 2002:aa7:d1ce:0:b0:64b:aa13:8b3e with SMTP id 4fb4d7f45d1cf-650747b71bals6341867a12.1.-pod-prod-02-eu;
 Mon, 12 Jan 2026 09:27:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVSSDBIHXQg6ohjBfSeCaRrXHPlvTtrnPBK19mBvgXCO214W4PKOITicUZnGXfWarv550e8plGVh3s=@googlegroups.com
X-Received: by 2002:a05:6402:2709:b0:64b:48b4:d71f with SMTP id 4fb4d7f45d1cf-65097dce8c0mr16127564a12.7.1768238859356;
        Mon, 12 Jan 2026 09:27:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768238859; cv=none;
        d=google.com; s=arc-20240605;
        b=VwzHH7/0XFWXHzCt/Y75xYtY0pXoN1kZHNrZoqsLKsVCKyX/1WM1+z4STzpDVlB8HP
         cmSJpBuadUCGOhk8k2n2MEbk9RTHxL/JEB64T737k1Cu0quthDoSr9+0arRIXUxYeDmC
         aWgZooo8JtC4iifDJEyFEmusn6p9v5n4cmIeQhKjIDUb8tpXu8+tWIjoUmevy5BkNQzl
         kRGKmnceiCUoy5Jkr8KwDHPNJQvnlAyAoI54ERh5VnFU39NYc7eTu3hrt9m7AJmNet+E
         dmSa3SX2z9Zaah0xfgblgh9F8JDhvpEDDbBBMc4TNRR6nXlJPkRlXEGimuWPvwt27KQa
         9Phw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=i82hVLnXXbAVfgARSkNfTSungiQEgJywgSx/RsX/wSc=;
        fh=KQTpgJjgWgujZ8ZmyMS6AtPV4WjP3gSWuDJQLdidzuc=;
        b=hAdgiOHvaOqPbR5zsxU6M83AW08o5qUsCVqkKImlhs239a1iJsW9kfWojXR7FnncBU
         USz8+ioTJ7BVvWHh2PbJKmXXZu23Zqr0X5vDD+tNey+3l1Xk3fHDkLEnAogU3lzc1874
         fN7XQ4ftYLqskZ+is3y8aNsbGzJAyjo9pXGy1pqUefu4I/HLYrLjXqJs0UGdCDe3rRYp
         I26XiIfuyvF269zQdN2gjSKxQdu1dl8W39ol7kv8J9d8XNKyHgKaTp6uhc5SgLw2qVRt
         xDkRT45BxsCUbg3F+QRuOPDhOS6HRAGoON4TReF/+iy3oEqQKEmSRYCd9hKCy0HxsVIh
         lq8Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=rp7WD2hz;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.101 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-43101.protonmail.ch (mail-43101.protonmail.ch. [185.70.43.101])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d70535dsi362569a12.3.2026.01.12.09.27.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 09:27:39 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.101 as permitted sender) client-ip=185.70.43.101;
Date: Mon, 12 Jan 2026 17:27:35 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nsc@kernel.org>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Subject: [PATCH v8 03/14] kasan: Fix inline mode for x86 tag-based mode
Message-ID: <1598e2bb7d45902fb0dc4d0d8e218f61b0c1a0f6.1768233085.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768233085.git.m.wieczorretman@pm.me>
References: <cover.1768233085.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: ca3467c5c544f1474f2a10b1278334b95255c44c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=rp7WD2hz;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.101 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

The LLVM compiler uses hwasan-instrument-with-calls parameter to setup
inline or outline mode in tag-based KASAN. If zeroed, it means the
instrumentation implementation will be pasted into each relevant
location along with KASAN related constants during compilation. If set
to one all function instrumentation will be done with function calls
instead.

The default hwasan-instrument-with-calls value for the x86 architecture
in the compiler is "1", which is not true for other architectures.
Because of this, enabling inline mode in software tag-based KASAN
doesn't work on x86 as the kernel script doesn't zero out the parameter
and always sets up the outline mode.

Explicitly zero out hwasan-instrument-with-calls when enabling inline
mode in tag-based KASAN.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Changelog v7:
- Add Alexander's Reviewed-by tag.

Changelog v6:
- Add Andrey's Reviewed-by tag.

Changelog v3:
- Add this patch to the series.

 scripts/Makefile.kasan | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 0ba2aac3b8dc..e485814df3e9 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -76,8 +76,11 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress
 RUSTFLAGS_KASAN := -Zsanitizer=kernel-hwaddress \
 		   -Zsanitizer-recover=kernel-hwaddress
 
+# LLVM sets hwasan-instrument-with-calls to 1 on x86 by default. Set it to 0
+# when inline mode is enabled.
 ifdef CONFIG_KASAN_INLINE
 	kasan_params += hwasan-mapping-offset=$(KASAN_SHADOW_OFFSET)
+	kasan_params += hwasan-instrument-with-calls=0
 else
 	kasan_params += hwasan-instrument-with-calls=1
 endif
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1598e2bb7d45902fb0dc4d0d8e218f61b0c1a0f6.1768233085.git.m.wieczorretman%40pm.me.
