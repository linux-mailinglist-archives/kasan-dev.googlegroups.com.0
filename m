Return-Path: <kasan-dev+bncBDI7FD5TRANRBOPVR23AMGQE3YMZTMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A39C9576A3
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2024 23:35:55 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2cb5847ff53sf5516400a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2024 14:35:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724103354; cv=pass;
        d=google.com; s=arc-20160816;
        b=cURGKJ4ZBwNpJerufuu04IDZiW9nFjL9+MXrgJD4Cvd9cir0EX8hh7Y60heeAzybRx
         R1eTTknhdOXsvqWlCI9nmHMGdrXp/pquWYvk9k8AsUqRB6x4l+tUGbhua85Boss5b06N
         zihM6/qYccIxOARfcmd61HSr1NaRmXsxIitFzSAO7diDbiNakPsa+sCQY+X01ln9zgCI
         MjsWyDWiwmQ9Ke4thGS3u4cRM07mUapK9e3llId7JrCuFImLU0QYQ+RlPFRQDn8vzRGX
         N0U6+hDcxWy05O8OgBLDwvbPnOtwGfpiRrAv+VLAILGoYN6ur+fF2IDWW3FQ9adehb1v
         xI4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=kFnhL6/JAvZFc7EMAkfkymtjI+NDqpfob7X1FUNpdG8=;
        fh=xIL+FyHlx1tL3BCBnfzgniYfqjRQHk2qWnXj46mdWiM=;
        b=0rfd6PPK+z+TE1OkpPxUFWx/Ig8GX/+fCYVbt/VZmPEliYUf3QjRVDddXclzhbUsm7
         BMLw8L4Wu4G0GCPqDCikoXfIQ3ouPpMYTklyqef1ZfrJOmm5ar2C+g/uQs4U3tiIw8km
         6ICw9xn/9iPW9sYZlzj/LhbGXVzYVVRhfVQpXE6jEuNhAFlV7roXKicHKKBGuSyyUEvq
         7EQk7SZYjzIoUQpH/ddRvJcbgAmd7IMcNBZePDKWl4dTH6RAlmhuPCVzWnASKameJPSu
         ytRsScS53+SzZEwEP5v5TAyx9EhQrbTiYpzOXcgaqaRb/n81pVXU1ijF654yThhJV4/w
         Wx4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bmI8EYNw;
       spf=pass (google.com: domain of 3t7rdzgckcxgiiwqnanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3t7rDZgcKCXgiiWqnanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724103354; x=1724708154; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kFnhL6/JAvZFc7EMAkfkymtjI+NDqpfob7X1FUNpdG8=;
        b=Q1EO3r6pAzWmsDgXUlF0RpZjpRik45MhYxJNnzdD3EBMvi2r8HhT7Ybi/dPeqArzo/
         guGCZ7S0giZkeR36rM/1JCUHSk2zsKH2/MD/BOxPtzkiPGEW1fNJK1X8gUL/tXuHPze7
         RPuE+PvRc+11q7jbFYYZWPxCAIE2Pj2Os4DupN7XjNXEAQpz9UNTirYeuJoGHkTbhpGh
         x6l6ihQFgirRiv41DwOD2If6hZrS6RRAw0LgAg7OomRL4zZVztWgaI/cWmitdu0+E26I
         0bKnj3AiDFF6Tjpl5XoXV4ow28+ObWu1JNAOXC0mXbFoJPUWPMbh7SlxuJTLI77Doejv
         NHNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724103354; x=1724708154;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kFnhL6/JAvZFc7EMAkfkymtjI+NDqpfob7X1FUNpdG8=;
        b=J8SKrbNyzUwUiB3WLUlsgGq5Demw25OwRFS/nz1FtXKckzGIS0vw46D7TM+sAoYmfq
         Q+5/cLc43QKnAouqvkxoO2rm0wj5fUvT3578N/6V4T6tc8goh4CV+BhZ4TsgqsAbVB3q
         Ax2kkd5sEaXC3nY5yrCf3FJTyEw736/BPt5+FLCle5R7Ig7wYPfxVeqhSMH7zQ3nAqqJ
         +auwMT0lv5KOI3AUHJi1b7zrm60XOcHwmWhmNDxVIcnpXdWwhBd6KuqtFJVoKiGcyQZK
         M1wVaaufLPtLP5r/98DH0jrxba2rMQigRjkGpRm9afhu5BaJEpCETmgwNMEoTJz+VAS5
         DJ9Q==
X-Forwarded-Encrypted: i=2; AJvYcCWj5ysV+6at21cXFpBcZ21z/rUVo6UDDcHVCjReoMD2W8+KDK6gmX+nc7UddHnVWdU9hNJa20t1duH3TA4cXDgPyATqOe2D1Q==
X-Gm-Message-State: AOJu0YzvC0We1YtwkK5NZ+NjK7khp9FuAUbHugt4kQ2MKmy/aQL4xqHd
	9g8giYefIVx7nFn9JEkHVGJhGrCQTxTt32Ltv3cNT6xnlQJaT5dI
X-Google-Smtp-Source: AGHT+IFjaJTjlydb1PtnZpcnO2ZXJ3QvG++udgdQah9NGHtT5y7vldIyYdiE/BWL0ThqOR3PKJANvw==
X-Received: by 2002:a17:90b:3602:b0:2cf:7cce:cc19 with SMTP id 98e67ed59e1d1-2d3dfc201c1mr13987418a91.6.1724103353789;
        Mon, 19 Aug 2024 14:35:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4d91:b0:2c6:ea3d:6fa2 with SMTP id
 98e67ed59e1d1-2d3c2a6a59dls3302557a91.0.-pod-prod-08-us; Mon, 19 Aug 2024
 14:35:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWT6xhgJsdcXplCoxCSS2LQAQZzzKjuwWKSrTi/qYRnF8h5HBRc6qUxoYIN0ILLDOWRfRDx1bg03YvQlMtB93gin+HTFJABkZQUsA==
X-Received: by 2002:a17:90a:ca93:b0:2cd:40ef:4764 with SMTP id 98e67ed59e1d1-2d3dfc489d8mr12657593a91.17.1724103352655;
        Mon, 19 Aug 2024 14:35:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724103352; cv=none;
        d=google.com; s=arc-20240605;
        b=a/OiFXWB4WVeDJUhDRJtl0lvZ9SkFbt0gGy+KQfs9Qz2EBKeisujK2GInsZsff3aI4
         t3JPA0k5H6NPt3vr9KjAl6054j9tU/YJfmqnhvx2z676BGA8Vd1QZqU1Eu2TMZe9poyH
         Sy6QAlVuCAWX+Fhb9IPAQ4XYmHFxBT4EykrSa8xOeDEH1JmHg2Pu9fBP1Fw7WTFUcgL+
         ulUlakHEiR/NhrtqmrEIDPvzZNyqFcQMv+QWYjZWvWjdJbKBv4FMNAVTyeUroHummqM3
         ZqECPdyVcVFvAikC7ztvUGnD98xs3dLLn1lKob7b1EqSVu7WIDqD/bvlE1WzO02Vfx4Q
         pWhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=nhd4bVGt7t2cMFreV83ln0lve5lvedn9wm7Lt/YZotw=;
        fh=ri0E4/QcxUepHvI6aAHoCEKWFWyYeplsaqj/BbPMkkk=;
        b=fy8kYwDw+l7dwJdayY7zOcUWTs9gUtnMHXvpJ36OdObzfFAn4CjGYf5v1icIUYi9eI
         H05Z55VphXpNbIBnLeYRi4iCP9GDHJDMmoMjzdWFXNvcO/n4VsA+VdZjnwzvOZWaKBGf
         SqYlWAlmleL7Pm8IdjzO1/12brAQZad06Su1UgsKBFxzwdpeVdgSnksGcw+cpX6wBUzN
         h6E/kE00ozUy5FEZw9tAgc3YydFHVBnAsAddoyhDhVtRYr/Rt7uyW0VIdLccjBkHjSrw
         ZOnp5KmupbMvP4uEj+w3qUN3bdYtGYubiqO4fo7r9EyzeM2096mAtKLwh7Ms6AbFhA8G
         AgUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=bmI8EYNw;
       spf=pass (google.com: domain of 3t7rdzgckcxgiiwqnanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3t7rDZgcKCXgiiWqnanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2d46aa9ee8fsi57838a91.2.2024.08.19.14.35.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Aug 2024 14:35:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3t7rdzgckcxgiiwqnanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--mmaurer.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6b8f13f2965so29775257b3.1
        for <kasan-dev@googlegroups.com>; Mon, 19 Aug 2024 14:35:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWvPLwAZPxNsf3Bz2v8VrI+Mjow+7SMAL59JlSfrrgnakvRTzWzIMYSTO0kuOytxxquUJPgJJpSEQ7EBstlpSJybQOK2HcUGaqYfA==
X-Received: from anyblade.c.googlers.com ([fda3:e722:ac3:cc00:20:ed76:c0a8:1791])
 (user=mmaurer job=sendgmr) by 2002:a25:6892:0:b0:e0b:a2a7:df77 with SMTP id
 3f1490d57ef6-e1180e64015mr158092276.2.1724103351771; Mon, 19 Aug 2024
 14:35:51 -0700 (PDT)
Date: Mon, 19 Aug 2024 21:35:21 +0000
In-Reply-To: <20240819213534.4080408-1-mmaurer@google.com>
Mime-Version: 1.0
References: <20240819213534.4080408-1-mmaurer@google.com>
X-Mailer: git-send-email 2.46.0.184.g6999bdac58-goog
Message-ID: <20240819213534.4080408-4-mmaurer@google.com>
Subject: [PATCH v3 3/4] rust: kasan: Rust does not support KHWASAN
From: "'Matthew Maurer' via kasan-dev" <kasan-dev@googlegroups.com>
To: dvyukov@google.com, ojeda@kernel.org, andreyknvl@gmail.com, 
	Alex Gaynor <alex.gaynor@gmail.com>, Wedson Almeida Filho <wedsonaf@gmail.com>, 
	Petr Mladek <pmladek@suse.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Yoann Congal <yoann.congal@smile.fr>, 
	Kees Cook <keescook@chromium.org>, Randy Dunlap <rdunlap@infradead.org>, 
	Alice Ryhl <aliceryhl@google.com>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	Vincent Guittot <vincent.guittot@linaro.org>
Cc: samitolvanen@google.com, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	glider@google.com, ryabinin.a.a@gmail.com, 
	Matthew Maurer <mmaurer@google.com>, Boqun Feng <boqun.feng@gmail.com>, Gary Guo <gary@garyguo.net>, 
	"=?UTF-8?q?Bj=C3=B6rn=20Roy=20Baron?=" <bjorn3_gh@protonmail.com>, Benno Lossin <benno.lossin@proton.me>, 
	Andreas Hindborg <a.hindborg@samsung.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	linux-kernel@vger.kernel.org, rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mmaurer@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=bmI8EYNw;       spf=pass
 (google.com: domain of 3t7rdzgckcxgiiwqnanckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--mmaurer.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3t7rDZgcKCXgiiWqnanckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--mmaurer.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Matthew Maurer <mmaurer@google.com>
Reply-To: Matthew Maurer <mmaurer@google.com>
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

Rust does not yet have support for software tags. Prevent RUST from
being selected if KASAN_SW_TAGS is enabled.

Signed-off-by: Matthew Maurer <mmaurer@google.com>
---
 init/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/init/Kconfig b/init/Kconfig
index 72404c1f2157..a8c3a289895e 100644
--- a/init/Kconfig
+++ b/init/Kconfig
@@ -1907,6 +1907,7 @@ config RUST
 	depends on !GCC_PLUGINS
 	depends on !RANDSTRUCT
 	depends on !DEBUG_INFO_BTF || PAHOLE_HAS_LANG_EXCLUDE
+	depends on !KASAN_SW_TAGS
 	help
 	  Enables Rust support in the kernel.
 
-- 
2.46.0.184.g6999bdac58-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240819213534.4080408-4-mmaurer%40google.com.
