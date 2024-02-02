Return-Path: <kasan-dev+bncBCF5XGNWYQBRBDEC6OWQMGQEWV36UTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 53A34846D8F
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Feb 2024 11:16:46 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-dc6dd6e4b49sf256563276.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Feb 2024 02:16:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706869005; cv=pass;
        d=google.com; s=arc-20160816;
        b=0pZezy79pRB9stGx9Per/oKKrLmy7TpalFoybiqGywV0Up3fS+aY7o9Xna1rs6F7Le
         ExdpwDo8zSG5VUUJgfdngumk6afmOIuOQzN4Su2IIoPL5Bi8Q4QoNh/HWhawYYCv1K2u
         1kQWU+K2QIdxQBoygA8WKMo1I1doX5QwQ8iUohUKEu6WkYLpn9J5OL645EvWzXIfpYJv
         BGeLWTtTLOz9hzstNwKmjRP+e2hzZgMxCTwJL8681RmBIVANsHbXjz5jG6KC0Eb0uQMk
         uefeutxQVs951NdfqoAqqmJboQ30rXBjsIAE2LY9PUanqako7egMTCmVCbZtnd1mQA3X
         QQhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=crwwLJR8v3qit5INtgZrxJi7vuZ/yPgiD/Obgz7FvOI=;
        fh=8Ip9LlsmXIfoh9amx+tCGwvJb5zC3KGDaQSr8voaKzE=;
        b=LuJa72KvU/X+O1qzgscXSUWnEe+J1xd6tFPUSZnHDPm6vETV963SPw93jKyJfeLdga
         yo7GGif+j/0sN1fctnzuGBOqNFp9azV2bv+YgkJx6EBNRhyCZAYCkNrm/hqSvG2u1Dri
         80UjTczTZUKtTkY5BvZkZ0jlRy/8Cdu3m69ueS7d45gZo85eyz/HhMqIn5RvFr45T4n5
         hHkDYaBmvRdF+CMPeel8NvwYYzKl/zG0ZrshUWqQRx7q+CWG+sG5uMJVyeRfH6hyIVZT
         A36JkEKy34Y+o78hGpgjz+mGS6ByOjrw7TRcDD5u+rNgXZr3oBW2k26fgOLuP67njDx7
         3QRw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=QCMg+7ht;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706869005; x=1707473805; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=crwwLJR8v3qit5INtgZrxJi7vuZ/yPgiD/Obgz7FvOI=;
        b=KsXidt41N4dokSOsWRsbcqEMHauitIBo42Yl2gMMqDhoK6efehtiIK/yq6BFWxohRW
         ILlxH0hrv5w5e4yhi68JbTepZ3TBGhMIBgUPHmoQ7jubKBtCGEuyY3kopdV+lx3aTlDJ
         zsLiq1dM6q7XSweVjSaJR3nXObpVvnQzw5o2KhHNURTo8XeUZtpcAswYaHj0l1uVgF7m
         5BPq16RaqXrTE9D2lBQr3nk2U3qUPfX1Yc1GzSr1lksHgZrceKI0KT8Rf1Qz2q+MYsn7
         qvJW/O4Q6Ej4pUmoRvDTKCyJIzWeyWaOp0ms4Gy8Vgjogas7YIaMND060nAkWxRSDc8B
         yv+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706869005; x=1707473805;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=crwwLJR8v3qit5INtgZrxJi7vuZ/yPgiD/Obgz7FvOI=;
        b=u5/Yh/GGxIBmvdh8/jYEl25lAGOKRaQNkEiqT/cUgTA6jQm9JI1ESHPE+wqNounuhS
         nP4pfbw0e714emHZJo8qv6DOdMcR6/jVuyZSpCmDiLv8LVdvseCOnT6hmESkqElWY1Cm
         qhqki0Xj3iNn77mrvBxD5s8SOBP9AoWL5Ax0VtvKyKKbgd+CQchX2nE7aj/FRM7v2s3+
         jH8xPNbgKSGt5MKc/ECHUb+Wr9vzxK56ZSGQ58YyLCMzOhO08Azt4jpUeuSGqydmfyE3
         1E1Tsj+3QnN+3DUUd9XiAYKBuG1T6Ul/kwUqpauNzxJ6SSnh3TelPP3W6r1N6r/jyye2
         Qlfg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCU/UbJw+wi/V3YSXklqr+KpIbSAcv2E1wZGrp3lEaz71g6wryMLQ6geyC+WfYPv/jt2ywbm522JHmUAdyCKBEdmsVMlAGNnPA==
X-Gm-Message-State: AOJu0YzaWD8Mbpf1MfcO6fSDTBOr5pmpR6VCQL0goXOn8/oOUD3o9Rw3
	vmvdg84ACc/MEBg8yJzJ//99YdltCYTSRzgrSNVcj0zVTBOlabi2
X-Google-Smtp-Source: AGHT+IHnRM1ztDtYZOkrJMN1Ll3gZ8VWoI2WvnYjodHdeajprGu2zuB9AsggYNalN+plst3MhAJMgw==
X-Received: by 2002:a25:adc6:0:b0:dc3:721f:7a53 with SMTP id d6-20020a25adc6000000b00dc3721f7a53mr7225490ybe.5.1706869004980;
        Fri, 02 Feb 2024 02:16:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d0d3:0:b0:dc2:2666:efc4 with SMTP id h202-20020a25d0d3000000b00dc22666efc4ls359559ybg.1.-pod-prod-01-us;
 Fri, 02 Feb 2024 02:16:44 -0800 (PST)
X-Received: by 2002:a81:ad54:0:b0:604:169a:6cc3 with SMTP id l20-20020a81ad54000000b00604169a6cc3mr6998372ywk.8.1706869004154;
        Fri, 02 Feb 2024 02:16:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706869004; cv=none;
        d=google.com; s=arc-20160816;
        b=gc2AOBnoXJjZzUFxCz9Qrlp0uhlCBMEnbyJjuC8c4fY5h88Kav+bLKeylv8MRKC/3o
         ypz3DOAGRi/My4ofBUikppCyc5J7+EgTznHOEzwsC6qPgHmLbnTfK0DkgGcyhEICYGNX
         4KyCjGAxCVbiL2WgvKjXi8GY3b0mNfQGzqkB0ZBkLpeEdIJBIk5M8PUatPMx3zdWnQp/
         7UdAg6ELFQ5Gv1WJh823wn9Chovj9/7Vc38FeXfccMfH/su459BIj2Za2f843FG5BAD8
         bdA67p02nVSsmuhMgmSRK629gc9tgD1bMaKYnKV2tevCzVXu55nrdIwyG0wvrO241iIC
         ti1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=U/S6R7/9nVoHmk9zF9Fu8HvJ6G5Gizsl3DGB5UcgoVw=;
        fh=OzfougGhLDlhICv1xIbJy5VDTWXuH7bfPUhro9gbJM4=;
        b=sKBbTxAnYJplEnNvyWhXzKKhREADwK+LgFjxMQqcM/bQwU+Ziqx+NSnCJqF+rUP11P
         +VtpNEHH76u+dJctJm0XQoGdJLg46/GyIY8VRbznb0RwwzCVbDmttCA9xlspFM7ArP1B
         3/N1hDMqq9dv9sjfjeVvKpV/Rkvcd+pQSQHZe1sh6hZrIY0PAWsGETUw3A5GmmYyGjTJ
         oPJupa6VsFXP/A+NPhKql8TBJheQK9jrWsOvWrrtSzXvoh1Mg4Jml7qiJhpZ7r7WP4Yy
         mdN2h4J/x0Hmfn0So63dVh0vTengQqSYxpteH5UtfoSkpH86mHULnSYAPyO+9Ft1y9/x
         1kUg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=QCMg+7ht;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=0; AJvYcCXF4btY2U7LwY0yu3tF2IlYZlAVek+bWd6+IH6BPGT0m3Ulb5pj+ZCsA5aASrzSW9KCOcaLONsi4HE0Z9kh578WxCM+60YSo90Sew==
Received: from mail-pg1-x533.google.com (mail-pg1-x533.google.com. [2607:f8b0:4864:20::533])
        by gmr-mx.google.com with ESMTPS id 9-20020ac85949000000b0042c0768d5fasi15650qtz.2.2024.02.02.02.16.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Feb 2024 02:16:44 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::533 as permitted sender) client-ip=2607:f8b0:4864:20::533;
Received: by mail-pg1-x533.google.com with SMTP id 41be03b00d2f7-5ce2aada130so1740923a12.1
        for <kasan-dev@googlegroups.com>; Fri, 02 Feb 2024 02:16:44 -0800 (PST)
X-Received: by 2002:a05:6a20:d80a:b0:19e:3172:b8ac with SMTP id iv10-20020a056a20d80a00b0019e3172b8acmr8509849pzb.22.1706869003182;
        Fri, 02 Feb 2024 02:16:43 -0800 (PST)
X-Forwarded-Encrypted: i=0; AJvYcCWoz46bwT+tJO8xy56NbLr1KS+igx2daYsByMo02TKngsVRwUuFg7rM8d2fC9gniw/eE1Q+M8gYLGV0R77HWl5kkLuEJZYFcd3ZpZKGRtahgInsMSopUwFERg7zuZHYNtJ5cJY9S2MraM2AOdZTTsl6P817jdn3+0hoVV2s43CNN5/nYeQK3ywIAd7TM2tMMv736L+PU5oEIuAwAF6QxY7hk6ZUYTxy0dptEOM02zqUvp11bDVVbi6S3n6ojbgp4xa9zL5Pl1AK7tfwa9hB2HWWUqQJAG1beGvKFdo7Mom3kiQCGh3TESzslYvSA98vnLsC4EJqMD9Uz8azrFX1Ex75q3xcLnhW2kZqdFqM+4BashtXkOJBquFxMijWLtVQMr4ZE2M1tUiRNGANdexlJ96uetelZ97X/PY/9FFiBdNHkgVQSScQTlNDriahUrbVN3f1x2A5SrEDHUYfRek4LjMjYi3p5UMVzy3MM2AYFHjg6ci4bdjFS8hPv4iQCGoeEYZuQp88sa54C908gCbMdO7a77djfDP9t5GC659+wIXuW5inYCBGQotSrYlfFNKhSKwT7bfBvkZuJCPGJTWGXk0+KPs/zoTpSkJ430g2C9DO1V/7d3r5Q6mZ8bhuHeko5NNBwMH5NODDFj2P6245q/GN+6UxZLLmpRUazUMVySJWK+qZCmIgUtRAeYTjxOxNK6dirVDW6ImDqWqJGDVldIDW+I7jV/5M5VWcgIUx4uDclV4lMY6o/UR8yI1NO/c=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id j24-20020a62b618000000b006dd850bbd21sm1236764pff.36.2024.02.02.02.16.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Feb 2024 02:16:42 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: linux-hardening@vger.kernel.org
Cc: Kees Cook <keescook@chromium.org>,
	Justin Stitt <justinstitt@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Marco Elver <elver@google.com>,
	Hao Luo <haoluo@google.com>,
	Przemek Kitszel <przemyslaw.kitszel@intel.com>,
	Fangrui Song <maskray@google.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Bill Wendling <morbo@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jonathan Corbet <corbet@lwn.net>,
	x86@kernel.org,
	linux-kernel@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	llvm@lists.linux.dev,
	linux-doc@vger.kernel.org,
	netdev@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-acpi@vger.kernel.org
Subject: [PATCH v2 2/6] ubsan: Reintroduce signed and unsigned overflow sanitizers
Date: Fri,  2 Feb 2024 02:16:35 -0800
Message-Id: <20240202101642.156588-2-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240202101311.it.893-kees@kernel.org>
References: <20240202101311.it.893-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=10079; i=keescook@chromium.org;
 h=from:subject; bh=81LcZge0w4D9Z3eA6B+rApaqgdau7DNMJpUzowyrc8U=;
 b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBlvMEHIaVk0RDXV5BS8oDSW+Q7mjUG3v2lN2MSh
 eQs8Xe4ZXyJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCZbzBBwAKCRCJcvTf3G3A
 JlV3EACFj6qzRW/Dmz2j427eAnNRW/hFiqg76oZtLKt19NBhwQSxqIEDMXQp9hgoLImHy3cIsTz
 /3Rn02fPcHAlgbHbphdnoxIxF9d3JIMOflSJOWUtksgIa2hMlnS7dKbdvmr6YMMT9DzhneaK/ah
 m8bVM9Mgc+Fzxr+ruzOV0BX8GlCxuFOL12H1D3nZvF82gmkuNPMCYslbh8l0P1WdKLSV4yEaD08
 RWG3VMBfMNhEMTzybJOFwIVklb0tu91BdUOI2awvdIBY0hXH+0T8ZI/JIgN0J39lmVCxQ2TuCZo
 JXBXbL0GsukvIx/3oo5JDt9pGOql4COz2gyh82QHnis0ssIlLtiNNgL23O0EDJOU00/BF81oVyA
 d58a5k99+BTYT48jsn1iwhsoIQaNvM2SQJcoE8FF6JeOqbElxHIUlp7L7ptRp6hNg2DFKQye4TZ
 DnJ1KTK0D9Se94Y/mmh2I1UBV/V6e+gaUPjzlq0ZVxwnNKlRtycg3Mjhv/0lTzGBlp+Bl+eE7g/
 7brRWwsZKFQ5Qgqu9kddHySyRFw4vwh55F6AqwHkg1EtoQWExp32wuEYmFa1j3Ap2p8TTTTlwVK
 dban4NYVGvUX/JjOynleWT2vjJ1Sz7/q5MFDcRNYcOuyP9b+jZPKfdD9BJHpPVkdE/OfPQV27r1 FhYPbS9aNfwli2Q==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=QCMg+7ht;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::533
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

Effectively revert commit 6aaa31aeb9cf ("ubsan: remove overflow
checks"), to allow the kernel to be built with the "overflow"
sanitizers again. This gives developers a chance to experiment[1][2][3]
with the instrumentation again, while compilers adjust their sanitizers
to deal with the impact of -fno-strict-oveflow (i.e. moving from
"overflow" checking to "wrap-around" checking).

Notably, the naming of the options is adjusted to use the name "WRAP"
instead of "OVERFLOW". In the strictest sense, arithmetic "overflow"
happens when a result exceeds the storage of the type, and is considered
by the C standard and compilers to be undefined behavior for signed
and pointer types (without -fno-strict-overflow). Unsigned arithmetic
overflow is defined as always wrapping around.

Because the kernel is built with -fno-strict-overflow, signed and pointer
arithmetic is defined to always wrap around instead of "overflowing"
(which could either be elided due to being undefined behavior or would
wrap around, which led to very weird bugs in the kernel).

So, the config options are added back as CONFIG_UBSAN_SIGNED_WRAP and
CONFIG_UBSAN_UNSIGNED_WRAP. Since the kernel has several places that
explicitly depend on wrap-around behavior (e.g. counters, atomics, crypto,
etc), also introduce the __signed_wrap and __unsigned_wrap function
attributes for annotating functions where wrapping is expected and should
not be instrumented. This will allow us to distinguish in the kernel
between intentional and unintentional cases of arithmetic wrap-around.

Additionally keep these disabled under CONFIG_COMPILE_TEST for now.

Link: https://github.com/KSPP/linux/issues/26 [1]
Link: https://github.com/KSPP/linux/issues/27 [2]
Link: https://github.com/KSPP/linux/issues/344 [3]
Cc: Justin Stitt <justinstitt@google.com>
Cc: Miguel Ojeda <ojeda@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nick Desaulniers <ndesaulniers@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>
Cc: Hao Luo <haoluo@google.com>
Cc: Przemek Kitszel <przemyslaw.kitszel@intel.com>
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 include/linux/compiler_types.h | 14 ++++++-
 lib/Kconfig.ubsan              | 19 ++++++++++
 lib/test_ubsan.c               | 49 ++++++++++++++++++++++++
 lib/ubsan.c                    | 68 ++++++++++++++++++++++++++++++++++
 lib/ubsan.h                    |  4 ++
 scripts/Makefile.ubsan         |  2 +
 6 files changed, 155 insertions(+), 1 deletion(-)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 6f1ca49306d2..e585614f3152 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -282,11 +282,23 @@ struct ftrace_likely_data {
 #define __no_sanitize_or_inline __always_inline
 #endif
 
+/* Allow wrapping arithmetic within an annotated function. */
+#ifdef CONFIG_UBSAN_SIGNED_WRAP
+# define __signed_wrap __attribute__((no_sanitize("signed-integer-overflow")))
+#else
+# define __signed_wrap
+#endif
+#ifdef CONFIG_UBSAN_UNSIGNED_WRAP
+# define __unsigned_wrap __attribute__((no_sanitize("unsigned-integer-overflow")))
+#else
+# define __unsigned_wrap
+#endif
+
 /* Section for code which can't be instrumented at all */
 #define __noinstr_section(section)					\
 	noinline notrace __attribute((__section__(section)))		\
 	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
-	__no_sanitize_memory
+	__no_sanitize_memory __signed_wrap __unsigned_wrap
 
 #define noinstr __noinstr_section(".noinstr.text")
 
diff --git a/lib/Kconfig.ubsan b/lib/Kconfig.ubsan
index 59e21bfec188..a7003e5bd2a1 100644
--- a/lib/Kconfig.ubsan
+++ b/lib/Kconfig.ubsan
@@ -116,6 +116,25 @@ config UBSAN_UNREACHABLE
 	  This option enables -fsanitize=unreachable which checks for control
 	  flow reaching an expected-to-be-unreachable position.
 
+config UBSAN_SIGNED_WRAP
+	bool "Perform checking for signed arithmetic wrap-around"
+	default UBSAN
+	depends on !COMPILE_TEST
+	depends on $(cc-option,-fsanitize=signed-integer-overflow)
+	help
+	  This option enables -fsanitize=signed-integer-overflow which checks
+	  for wrap-around of any arithmetic operations with signed integers.
+
+config UBSAN_UNSIGNED_WRAP
+	bool "Perform checking for unsigned arithmetic wrap-around"
+	depends on $(cc-option,-fsanitize=unsigned-integer-overflow)
+	depends on !X86_32 # avoid excessive stack usage on x86-32/clang
+	depends on !COMPILE_TEST
+	help
+	  This option enables -fsanitize=unsigned-integer-overflow which checks
+	  for wrap-around of any arithmetic operations with unsigned integers. This
+	  currently causes x86 to fail to boot.
+
 config UBSAN_BOOL
 	bool "Perform checking for non-boolean values used as boolean"
 	default UBSAN
diff --git a/lib/test_ubsan.c b/lib/test_ubsan.c
index 2062be1f2e80..84d8092d6c32 100644
--- a/lib/test_ubsan.c
+++ b/lib/test_ubsan.c
@@ -11,6 +11,51 @@ typedef void(*test_ubsan_fp)(void);
 			#config, IS_ENABLED(config) ? "y" : "n");	\
 	} while (0)
 
+static void test_ubsan_add_overflow(void)
+{
+	volatile int val = INT_MAX;
+	volatile unsigned int uval = UINT_MAX;
+
+	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
+	val += 2;
+
+	UBSAN_TEST(CONFIG_UBSAN_UNSIGNED_WRAP);
+	uval += 2;
+}
+
+static void test_ubsan_sub_overflow(void)
+{
+	volatile int val = INT_MIN;
+	volatile unsigned int uval = 0;
+	volatile int val2 = 2;
+
+	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
+	val -= val2;
+
+	UBSAN_TEST(CONFIG_UBSAN_UNSIGNED_WRAP);
+	uval -= val2;
+}
+
+static void test_ubsan_mul_overflow(void)
+{
+	volatile int val = INT_MAX / 2;
+	volatile unsigned int uval = UINT_MAX / 2;
+
+	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
+	val *= 3;
+
+	UBSAN_TEST(CONFIG_UBSAN_UNSIGNED_WRAP);
+	uval *= 3;
+}
+
+static void test_ubsan_negate_overflow(void)
+{
+	volatile int val = INT_MIN;
+
+	UBSAN_TEST(CONFIG_UBSAN_SIGNED_WRAP);
+	val = -val;
+}
+
 static void test_ubsan_divrem_overflow(void)
 {
 	volatile int val = 16;
@@ -90,6 +135,10 @@ static void test_ubsan_misaligned_access(void)
 }
 
 static const test_ubsan_fp test_ubsan_array[] = {
+	test_ubsan_add_overflow,
+	test_ubsan_sub_overflow,
+	test_ubsan_mul_overflow,
+	test_ubsan_negate_overflow,
 	test_ubsan_shift_out_of_bounds,
 	test_ubsan_out_of_bounds,
 	test_ubsan_load_invalid_value,
diff --git a/lib/ubsan.c b/lib/ubsan.c
index df4f8d1354bb..5fc107f61934 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -222,6 +222,74 @@ static void ubsan_epilogue(void)
 	check_panic_on_warn("UBSAN");
 }
 
+static void handle_overflow(struct overflow_data *data, void *lhs,
+			void *rhs, char op)
+{
+
+	struct type_descriptor *type = data->type;
+	char lhs_val_str[VALUE_LENGTH];
+	char rhs_val_str[VALUE_LENGTH];
+
+	if (suppress_report(&data->location))
+		return;
+
+	ubsan_prologue(&data->location, type_is_signed(type) ?
+			"signed-integer-overflow" :
+			"unsigned-integer-overflow");
+
+	val_to_string(lhs_val_str, sizeof(lhs_val_str), type, lhs);
+	val_to_string(rhs_val_str, sizeof(rhs_val_str), type, rhs);
+	pr_err("%s %c %s cannot be represented in type %s\n",
+		lhs_val_str,
+		op,
+		rhs_val_str,
+		type->type_name);
+
+	ubsan_epilogue();
+}
+
+void __ubsan_handle_add_overflow(void *data,
+				void *lhs, void *rhs)
+{
+
+	handle_overflow(data, lhs, rhs, '+');
+}
+EXPORT_SYMBOL(__ubsan_handle_add_overflow);
+
+void __ubsan_handle_sub_overflow(void *data,
+				void *lhs, void *rhs)
+{
+	handle_overflow(data, lhs, rhs, '-');
+}
+EXPORT_SYMBOL(__ubsan_handle_sub_overflow);
+
+void __ubsan_handle_mul_overflow(void *data,
+				void *lhs, void *rhs)
+{
+	handle_overflow(data, lhs, rhs, '*');
+}
+EXPORT_SYMBOL(__ubsan_handle_mul_overflow);
+
+void __ubsan_handle_negate_overflow(void *_data, void *old_val)
+{
+	struct overflow_data *data = _data;
+	char old_val_str[VALUE_LENGTH];
+
+	if (suppress_report(&data->location))
+		return;
+
+	ubsan_prologue(&data->location, "negation-overflow");
+
+	val_to_string(old_val_str, sizeof(old_val_str), data->type, old_val);
+
+	pr_err("negation of %s cannot be represented in type %s:\n",
+		old_val_str, data->type->type_name);
+
+	ubsan_epilogue();
+}
+EXPORT_SYMBOL(__ubsan_handle_negate_overflow);
+
+
 void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
 {
 	struct overflow_data *data = _data;
diff --git a/lib/ubsan.h b/lib/ubsan.h
index 5d99ab81913b..0abbbac8700d 100644
--- a/lib/ubsan.h
+++ b/lib/ubsan.h
@@ -124,6 +124,10 @@ typedef s64 s_max;
 typedef u64 u_max;
 #endif
 
+void __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
+void __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
+void __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
+void __ubsan_handle_negate_overflow(void *_data, void *old_val);
 void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
 void __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
 void __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
index 7cf42231042b..7b2f3d554c59 100644
--- a/scripts/Makefile.ubsan
+++ b/scripts/Makefile.ubsan
@@ -8,6 +8,8 @@ ubsan-cflags-$(CONFIG_UBSAN_LOCAL_BOUNDS)	+= -fsanitize=local-bounds
 ubsan-cflags-$(CONFIG_UBSAN_SHIFT)		+= -fsanitize=shift
 ubsan-cflags-$(CONFIG_UBSAN_DIV_ZERO)		+= -fsanitize=integer-divide-by-zero
 ubsan-cflags-$(CONFIG_UBSAN_UNREACHABLE)	+= -fsanitize=unreachable
+ubsan-cflags-$(CONFIG_UBSAN_SIGNED_WRAP)	+= -fsanitize=signed-integer-overflow
+ubsan-cflags-$(CONFIG_UBSAN_UNSIGNED_WRAP)	+= -fsanitize=unsigned-integer-overflow
 ubsan-cflags-$(CONFIG_UBSAN_BOOL)		+= -fsanitize=bool
 ubsan-cflags-$(CONFIG_UBSAN_ENUM)		+= -fsanitize=enum
 ubsan-cflags-$(CONFIG_UBSAN_TRAP)		+= $(call cc-option,-fsanitize-trap=undefined,-fsanitize-undefined-trap-on-error)
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240202101642.156588-2-keescook%40chromium.org.
