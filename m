Return-Path: <kasan-dev+bncBD53XBUFWQDBBEFKZDEAMGQEDYPBQUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13c.google.com (mail-yx1-xb13c.google.com [IPv6:2607:f8b0:4864:20::b13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F25EC48025
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:38:41 +0100 (CET)
Received: by mail-yx1-xb13c.google.com with SMTP id 956f58d0204a3-63e3a044ec7sf4148950d50.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:38:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792720; cv=pass;
        d=google.com; s=arc-20240605;
        b=beMWJMe9JhW7NjAM0Cd2VQnmFdJFn+tnGyAzagHzp26ZIYn4qtCDQdniy7I2s1s3P5
         gvbBLXp+UJmETR08g2pt+B+vxOdMwM7abkaNE2cosVEKLcQUDGTmi3YEAUCS9wsUo9ar
         pGQ5AsaoYA6BRHCHwCYa8KICyCUXg7VDBYU4uO4qhzKKG/xTf9SwXE/GxwafYVUxUHOa
         y/L8MLQtU/opshcsKdtyYMonk0tTIAzaOhV7LVnPJUqvWMiAiJOSiJuZngdExcs0Kyi+
         EK6cbh4D96XaWvNJXBmuii5beZDmStQUB/+/DuHV2tAH9SZa/DfAwMQEeuIqwrIHw2Je
         07SQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:to:from
         :sender:dkim-signature:dkim-signature;
        bh=CgnkeJQMxvbJidMMpwXADNaP42Du1c7DXKZeBAY8UM0=;
        fh=NfTKzVnVXPJRdtNvArFN1aiqlutw0oPqnaL020Etov4=;
        b=J7kKdXS1cBeJMH+p+EJvwXLsWlpdxeRBwLd9hyfSGwo+a4gKPRsM6a1lV0Dfv+cA25
         vBSS4LUsPrZRtfwaUX4dXM5V1awryflWYtgO3sVK5UyYXPBiQ9/+g/r9KHEDylJQDqDs
         10elmdgONwwPp1ubQSHR+17U/TMG+mfxnIWXdROI8g9TSqV2ZYRqjmQXwLArkeSQKtWw
         GGsnsKO91YaMhZ9TaqJaB93tE0uvJIweadlLOxBUFb0xFDPE5Qff0F+CbhZftfB/GLPL
         5+zhWsk+dTbIo2w8URRGvUD3U66i73X6ByTs4PTU+h+zVhpwb1uud5ycoFtmWwFb1TXf
         IafA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=drGgwfb2;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792720; x=1763397520; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CgnkeJQMxvbJidMMpwXADNaP42Du1c7DXKZeBAY8UM0=;
        b=K0X1Cmv658K3MnSXD959Z3k90C7KBWVUVg7DyftfmR3BUht7fZ7WlP5ouSloWrgqcF
         hkMaqzo0XWfhVlUV4+mgFMGleyE+Puo4rggIalQIgGdqtq7eZOMAF6hOpDv3zRpNC3/z
         rAqjrN5oj/Zby/3pgUyOml8wsv62YagFsNK94GpNmMXImvfB5SZKThU7/wWMHG52LVcL
         TG85ZGCESRdhzHXOahVWn5v5CF9R9jDqQL4mf6ahzYBacG90LqXLoZAC/lIflENwmvzP
         AQNS7BCyUfcNqR2Y//oMSEBa5JlLmykN5VNEPmDXEdfkYPICpIjrY+PYFmPWpwYDSLex
         HXTg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792720; x=1763397520; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CgnkeJQMxvbJidMMpwXADNaP42Du1c7DXKZeBAY8UM0=;
        b=Z7AEciUrrUdoA/BXE5i2mmRzKLDWi5IsOPOnu+711zACMX330kMsZIupZyE6cKPiCd
         mSHj8kiadrOQsQTFiOgbnCWToqpUCTAHlpaLWFyLAa20GgKDPfithPBHaOsXtyqet9lc
         AOYO9UKtXXSpdT62DA46DTSD0fzBQnxPg3zC0FH9a+Eh8yaBoY+oljSSE7v/hAFHVx1q
         9SfuqYwOvt4eTimKbS0vd/FwDVrapqoSI+Oe0NGDEkL6+zVNlfHQCOk4l6xQfqqm+XXB
         ucIIsDARhBcaqaRmOGoZYJCn2nmx4UEfjVux6MnDS99W/+atj4pJpYTQBmzK0Z9cHrQ5
         VWfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792720; x=1763397520;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CgnkeJQMxvbJidMMpwXADNaP42Du1c7DXKZeBAY8UM0=;
        b=WwC9YKeD0c/cKum00ha8QyqqyoGtptF5PGa//NiG4Vv+njreeM38lA3H+h8liUFUNT
         UnZ9XRXteHVKYXsva12Ubi2++kXhpCfQaXqfJeZ3pHcZ9nc+PmfTX82MVo/HeARM584p
         uiUsqa2M0gv4eFBCpLh8WX9rmSns8XibjCC4J0vn7cbY+aaXP9d+TQQFkLUXyKSQKTLy
         A/Mwe3R9Xch0LPLn5RNqGvlJRTtID5jAn9kMrpIFYhXvm//II344CFI/7VZQGTVIdjGu
         +5lxzNDrS5s9so2Z8ChcyKKVWRdsknp3OuoJVQofKJnggp1CajtU1Kt6/i3tBBnsj3Pz
         I/5A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVSjS4qkUEYbOQT0ASstTdt8hG6S5isdTz5YVOY+nMHxrP6XSokFxZcxIY1tkc3r1xm5+d0oQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxn37H+iexfW/a/8rY1VUBnfm/t3q7D+8H1VAiB7W6NhuwYYQ6K
	GyTHL19HM/8UJuv7kuw0m+4vDyJOWo9e41XfZz591mV4om/Aogk/ARik
X-Google-Smtp-Source: AGHT+IE2SCaAtXmMxBwJMHm+WilLJ/WF3t7Ia3hsCXmKpsyDQRcWPE51hLZysCTL9cTDUuTjUyrA+g==
X-Received: by 2002:a05:690e:42c8:b0:63f:b3f0:42f9 with SMTP id 956f58d0204a3-640d45d5df9mr5871160d50.57.1762792720292;
        Mon, 10 Nov 2025 08:38:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YkjYB5t4ynKNpziAg+/V1s+zGtqhtpCiR2Xso8J7uTqg=="
Received: by 2002:a05:690e:12:b0:5f3:b863:1e52 with SMTP id
 956f58d0204a3-640b55311f0ls4112221d50.0.-pod-prod-03-us; Mon, 10 Nov 2025
 08:38:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWbBz8qVlK4+JC/MfGqBSV0Fc3s0ob+A46o7cgp/BMoSDCKhQoiKimBK+jqbCwebtFVs5K/AY38qCU=@googlegroups.com
X-Received: by 2002:a05:690c:a91:b0:787:fec5:7090 with SMTP id 00721157ae682-787fec5828fmr13671637b3.10.1762792719436;
        Mon, 10 Nov 2025 08:38:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792719; cv=none;
        d=google.com; s=arc-20240605;
        b=I92IHihwYzw27CHi0jSREnirNKdphye65wedhcF8jPG9Ss31uddfozAYDFl85InptX
         J5Ue9HeVSnlghJ96z0bHNSK9Eda98zxMt/KiAdFm/56ZPayUTLADTqSwFeEPEppdi1GZ
         /io8VFAbg1Zk0Kkpsl+VWMY9GtbgyJ5pFJBG4G5P2gitdPoh+1qqkC7KX4T4VYqSHTim
         hDpxoLUhVp/kr75c7JHJkfOxwARxAQXFc3EM5auLky+tYPw2ebJefLdKEMFAbArnvDII
         Hva0F9CBsYKSkAJsVq0pV4BQ88pTQwSTqHy9LwrI/rf0zOlxFSq502NJcOFBOwAL/Z1C
         vyPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=1OccL0Sq4R/RA62B7XB61l1HOYHt90e9E66Mfl8uInY=;
        fh=v0P/bc3eezuxTxjJlsoiUsfJtC31Kf6dQDLmHUsCE/Y=;
        b=B73ALVYGuivpk3SSz/JZo/CCTbzy/XSawDlA+2i3+mGdGW2q6Dq35H69IYmd3i+TdN
         KEIIsjjnLO/TQaGoZ71YFAy0JBsB4bbsi65x6sWThIGveSwavD/idGpsvmRWwyey7u0C
         ZN1pxFzZGbwAfGpsozPzer9d/UNktw+kbZfMGvPXXsJz09wQMUANj0GRQNX3WjA0hOcr
         gsMfAR+a4QLyjSIO1REDtgVSX7Yd5SRzf1BYAke2VVpUkUpCteg/z2kqDe+Z1oZNNuUP
         mabZRhcfCrOwn/skoqRPt0MvtqMjPfpu7d2qOkGJWvZbdnJuiQfr4FKRy2s3+IHw97hP
         lbqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=drGgwfb2;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-787d67fe872si4022857b3.2.2025.11.10.08.38.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:38:39 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-ba599137cf7so2456673a12.0
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:38:39 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUgFe60mfc9SV+xlsYMtgm9KrghQrnZcAyR3TNxmoFvqwf2LbfrZBLsBQEkv2w+rnd2A8E8VqipEn8=@googlegroups.com
X-Gm-Gg: ASbGncsuCEiDCM2eJEEBR/3KWVbr1Gea+ygtXtxFT7gdO/xYMwrc4qPzIktKoI41e+b
	VVZy+c6kgzt/u42q4xDf7kNGmAY2cp/62uiXmbwYxx8Zdn+Uz1obhY4Pfu45K0snTGfnC3kSe9i
	QvsNCWE+EnReoD6odQ3X+24x0aNZBI356OnxaPMhUlxSoA5GDBP0cQCeYDtWfqD7if5XI4bBjXw
	mheVpKKLW24DoZMzM8y9r73OCUjMcsRbf5uItVeG7lMJjzJdgyGns3uOouy/NaSfS0CacbSn9VB
	FvuoDg3+YCnu7hhm89u52M8aDh38xIdhuvEoWDWiWnk1kTXIsCahTCInVhf2aMI/Ul/2PscJo+J
	cgpP1kqHzsQ+6ex002IfcNtjD/WeLFt4EV7amcrHm4QMjfGarYVjvM94RYR/i7g9a/VndlIlFCs
	AfMtUMHB/a+lg=
X-Received: by 2002:a17:902:cec7:b0:295:9db1:ff32 with SMTP id d9443c01a7336-297e56dc7b2mr114908455ad.48.1762792718180;
        Mon, 10 Nov 2025 08:38:38 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29650c5e5bdsm150563255ad.39.2025.11.10.08.38.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:38:37 -0800 (PST)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	"Masami Hiramatsu (Google)" <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Alice Ryhl <aliceryhl@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ben Segall <bsegall@google.com>,
	Bill Wendling <morbo@google.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	David Kaplan <david.kaplan@amd.com>,
	"David S. Miller" <davem@davemloft.net>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Ian Rogers <irogers@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	James Clark <james.clark@linaro.org>,
	Jinchao Wang <wangjinchao600@gmail.com>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Juri Lelli <juri.lelli@redhat.com>,
	Justin Stitt <justinstitt@google.com>,
	kasan-dev@googlegroups.com,
	Kees Cook <kees@kernel.org>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	"Liang Kan" <kan.liang@linux.intel.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	linux-arm-kernel@lists.infradead.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-perf-users@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Mel Gorman <mgorman@suse.de>,
	Michal Hocko <mhocko@suse.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nam Cao <namcao@linutronix.de>,
	Namhyung Kim <namhyung@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Naveen N Rao <naveen@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Rong Xu <xur@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <thomas.weissschuh@linutronix.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Will Deacon <will@kernel.org>,
	workflows@vger.kernel.org,
	x86@kernel.org
Subject: [PATCH v8 26/27] docs: add KStackWatch document
Date: Tue, 11 Nov 2025 00:36:21 +0800
Message-ID: <20251110163634.3686676-27-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=drGgwfb2;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Add documentation for KStackWatch under Documentation/.

It provides an overview, main features, usage details, configuration
parameters, and example scenarios with test cases. The document also
explains how to locate function offsets and interpret logs.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 Documentation/dev-tools/index.rst       |   1 +
 Documentation/dev-tools/kstackwatch.rst | 377 ++++++++++++++++++++++++
 2 files changed, 378 insertions(+)
 create mode 100644 Documentation/dev-tools/kstackwatch.rst

diff --git a/Documentation/dev-tools/index.rst b/Documentation/dev-tools/in=
dex.rst
index 4b8425e348ab..272ae9b76863 100644
--- a/Documentation/dev-tools/index.rst
+++ b/Documentation/dev-tools/index.rst
@@ -32,6 +32,7 @@ Documentation/process/debugging/index.rst
    lkmm/index
    kfence
    kselftest
+   kstackwatch
    kunit/index
    ktap
    checkuapi
diff --git a/Documentation/dev-tools/kstackwatch.rst b/Documentation/dev-to=
ols/kstackwatch.rst
new file mode 100644
index 000000000000..9b710b90e512
--- /dev/null
+++ b/Documentation/dev-tools/kstackwatch.rst
@@ -0,0 +1,377 @@
+.. SPDX-License-Identifier: GPL-2.0
+
+=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D
+Kernel Stack Watch (KStackWatch)
+=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D
+
+Overview
+=3D=3D=3D=3D=3D=3D=3D=3D
+
+KStackWatch is a lightweight debugging tool designed to detect kernel stac=
k
+corruption in real time. It installs a hardware breakpoint (watchpoint) at=
 a
+function's specified offset using *kprobe.post_handler* and removes it in
+*fprobe.exit_handler*. This covers the full execution window and reports
+corruption immediately with time, location, and call stack.
+
+Main features:
+
+* Immediate and precise stack corruption detection
+* Support for multiple concurrent watchpoints with configurable limits
+* Lockless design, usable in any context
+* Depth filter for recursive calls
+* Low overhead of memory and CPU
+* Flexible debugfs configuration with key=3Dval syntax
+* Architecture support: x86_64 and arm64
+* Auto-canary detection to simplify configuration
+
+Performance Impact
+=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
+
+Runtime overhead was measured on Intel Core Ultra 5 125H @ 3 GHz running
+kernel 6.17, using test4:
+
++------------------------+-------------+---------+
+| Type                   | Time (ns)   | Cycles  |
++=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D+=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D+=3D=3D=3D=3D=3D=3D=3D=3D=3D+
+| entry with watch       | 10892       | 32620   |
++------------------------+-------------+---------+
+| entry without watch    | 159         | 466     |
++------------------------+-------------+---------+
+| exit with watch        | 12541       | 37556   |
++------------------------+-------------+---------+
+| exit without watch     | 124         | 369     |
++------------------------+-------------+---------+
+
+From a broader perspective, the overall comparison is as follows:
+
++----------------------------+----------------------+---------------------=
----+
+| Mode                       | CPU Overhead (add)   | Memory Overhead (add=
)   |
++=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D+=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D+=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D+
+| Compiled but not enabled   | None                 | ~20 B per task      =
    |
++----------------------------+----------------------+---------------------=
----+
+| Enabled, no function hit   | None                 | ~few hundred B      =
    |
++----------------------------+----------------------+---------------------=
----+
+| Func hit, HWBP not toggled | ~140 ns per call     | None                =
    |
++----------------------------+----------------------+---------------------=
----+
+| Func hit, HWBP toggled     | ~11=E2=80=9312 =C2=B5s per call   | None   =
                 |
++----------------------------+----------------------+---------------------=
----+
+
+The overhead is minimal, making KStackWatch suitable for production
+environments where stack corruption is suspected but kernel rebuilds are n=
ot
+feasible.
+
+Kconfig Options
+=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
+
+The following configuration options control KStackWatch builds:
+
+- CONFIG_KSTACKWATCH
+
+  Builds the kernel with KStackWatch enabled.
+
+- CONFIG_KSTACKWATCH_PROFILING
+
+  Measures probe runtime overhead for performance analysis and tuning.
+
+- CONFIG_KSTACKWATCH_TEST
+
+  Builds a test module to validate KStackWatch functionality.
+
+Usage
+=3D=3D=3D=3D=3D
+
+KStackWatch provides optional configurations for different use cases.
+CONFIG_KSTACKWATCH enables real-time stack corruption detection using hard=
ware breakpoints and probes.
+CONFIG_KSTACKWATCH_PROFILING allows measurement of probe latency and overh=
ead for performance analysis.
+CONFIG_KSTACKWATCH_TEST builds a test module for validating KStackWatch fu=
nctionality under controlled conditions.
+
+KStackWatch is configured through */sys/kernel/debug/kstackwatch/config* u=
sing a
+key=3Dvalue format. Both long and short forms are supported. Writing an em=
pty
+string disables the watch.
+
+.. code-block:: bash
+
+	# long form
+	echo func_name=3D? func_offset=3D? ... > /sys/kernel/debug/kstackwatch/co=
nfig
+
+	# short form
+	echo fn=3D? fo=3D? ... > /sys/kernel/debug/kstackwatch/config
+
+	# disable
+	echo > /sys/kernel/debug/kstackwatch/config
+
+The func_name and the func_offset where the watchpoint should be placed mu=
st be
+known. This information can be obtained from *objdump* or other tools.
+
+Required parameters
+--------------------
+
++--------------+--------+-----------------------------------------+
+| Parameter    | Short  | Description                             |
++=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D+=3D=3D=3D=3D=3D=3D=3D=3D+=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D+
+| func_name    | fn     | Name of the target function             |
++--------------+--------+-----------------------------------------+
+| func_offset  | fo     | Instruction pointer offset              |
++--------------+--------+-----------------------------------------+
+
+Optional parameters
+--------------------
+
+Default 0 and can be omitted.
+Both decimal and hexadecimal are supported.
+
++--------------+--------+------------------------------------------------+
+| Parameter    | Short  | Description                                    |
++=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D+=3D=3D=3D=3D=3D=3D=3D=3D+=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D+
+| auto_canary  | ac     | Automatically calculated canary sp_offset      |
++--------------+--------+------------------------------------------------+
+| depth        | dp     | Recursion depth filter                         |
++--------------+--------+------------------------------------------------+
+|              |        | Maximum number of concurrent watchpoints       |
+| max_watch    | mw     | (default 0, capped by available hardware       |
+|              |        | breakpoints)                                   |
++--------------+--------+------------------------------------------------+
+| panic_hit    | ph     | Panic system on watchpoint hit (default 0)     |
++--------------+--------+------------------------------------------------+
+| sp_offset    | so     | Watching addr offset from stack pointer        |
++--------------+--------+------------------------------------------------+
+| watch_len    | wl     | Watch length in bytes (1, 2, 4, 8 onX86_64)    |
++--------------+--------+------------------------------------------------+
+
+
+Workflow Example
+=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
+
+Silent corruption
+-----------------
+
+Consider *test3* in *kstackwatch_test.sh*. Run it directly:
+
+.. code-block:: bash
+
+	echo test3 >/sys/kernel/debug/kstackwatch/test
+
+Sometimes, *test_mthread_victim()* may report as unhappy:
+
+.. code-block:: bash
+
+	[    7.807082] kstackwatch_test: victim[0][11]: unhappy buf[8]=3D0xabcdab=
cd
+
+Its source code is:
+
+.. code-block:: c
+
+	static void test_mthread_victim(int thread_id, int seq_id, u64 start_ns)
+	{
+		ulong buf[BUFFER_SIZE];
+
+		for (int j =3D 0; j < BUFFER_SIZE; j++)
+			buf[j] =3D 0xdeadbeef + seq_id;
+
+		if (start_ns)
+			silent_wait_us(start_ns, VICTIM_MINIOR_WAIT_NS);
+
+		for (int j =3D 0; j < BUFFER_SIZE; j++) {
+			if (buf[j] !=3D (0xdeadbeef + seq_id)) {
+				pr_warn("victim[%d][%d]: unhappy buf[%d]=3D0x%lx\n",
+					thread_id, seq_id, j, buf[j]);
+				return;
+			}
+		}
+
+		pr_info("victim[%d][%d]: happy\n", thread_id, seq_id);
+	}
+
+From the source code, the report indicates buf[8] was unexpectedly modifie=
d,
+a case of silent corruption.
+
+Configuration
+-------------
+
+Since buf[8] is the corrupted variable, the following configuration shows
+how to use KStackWatch to detect its corruption.
+
+func_name
+~~~~~~~~~~~
+
+As seen, buf[8] is initialized and modified in *test_mthread_victim*\(\) ,
+which sets *func_name*.
+
+func_offset & sp_offset
+~~~~~~~~~~~~~~~~~~~~~~~~~
+The watchpoint should be set after the assignment and as close as
+possible, which sets *func_offset*.
+
+The watchpoint should be set to watch buf[8], which sets *sp_offset*.
+
+Use the objdump output to disassemble the function:
+
+.. code-block:: bash
+
+	objdump -S --disassemble=3Dtest_mthread_victim vmlinux
+
+A shortened output is:
+
+.. code-block:: text
+
+	static void test_mthread_victim(int thread_id, int seq_id, u64 start_ns)
+	{
+	ffffffff815cb4e0:       e8 5b 9b ca ff          call   ffffffff81275040 <=
__fentry__>
+	ffffffff815cb4e5:       55                      push   %rbp
+	ffffffff815cb4e6:       53                      push   %rbx
+	ffffffff815cb4e7:       48 81 ec 08 01 00 00    sub    $0x108,%rsp
+	ffffffff815cb4ee:       89 fd                   mov    %edi,%ebp
+	ffffffff815cb4f0:       89 f3                   mov    %esi,%ebx
+	ffffffff815cb4f2:       49 89 d0                mov    %rdx,%r8
+	ffffffff815cb4f5:       65 48 8b 05 0b cb 80    mov    %gs:0x280cb0b(%rip=
),%rax        # ffffffff83dd8008 <__stack_chk_guard>
+	ffffffff815cb4fc:       02
+	ffffffff815cb4fd:       48 89 84 24 00 01 00    mov    %rax,0x100(%rsp)
+	ffffffff815cb504:       00
+	ffffffff815cb505:       31 c0                   xor    %eax,%eax
+		ulong buf[BUFFER_SIZE];
+	ffffffff815cb507:       48 89 e2                mov    %rsp,%rdx
+	ffffffff815cb50a:       b9 20 00 00 00          mov    $0x20,%ecx
+	ffffffff815cb50f:       48 89 d7                mov    %rdx,%rdi
+	ffffffff815cb512:       f3 48 ab                rep stos %rax,%es:(%rdi)
+
+		for (int j =3D 0; j < BUFFER_SIZE; j++)
+	ffffffff815cb515:       eb 10                   jmp    ffffffff815cb527 <=
test_mthread_victim+0x47>
+			buf[j] =3D 0xdeadbeef + seq_id;
+	ffffffff815cb517:       8d 93 ef be ad de       lea    -0x21524111(%rbx),=
%edx
+	ffffffff815cb51d:       48 63 c8                movslq %eax,%rcx
+	ffffffff815cb520:       48 89 14 cc             mov    %rdx,(%rsp,%rcx,8)
+	ffffffff815cb524:       83 c0 01                add    $0x1,%eax
+	ffffffff815cb527:       83 f8 1f                cmp    $0x1f,%eax
+	ffffffff815cb52a:       7e eb                   jle    ffffffff815cb517 <=
test_mthread_victim+0x37>
+		if (start_ns)
+	ffffffff815cb52c:       4d 85 c0                test   %r8,%r8
+	ffffffff815cb52f:       75 21                   jne    ffffffff815cb552 <=
test_mthread_victim+0x72>
+			silent_wait_us(start_ns, VICTIM_MINIOR_WAIT_NS);
+	...
+	ffffffff815cb571:       48 8b 84 24 00 01 00    mov    0x100(%rsp),%rax
+	ffffffff815cb579:       65 48 2b 05 87 ca 80    sub    %gs:0x280ca87(%rip=
),%rax        # ffffffff83dd8008 <__stack_chk_guard>
+	...
+	ffffffff815cb5a1:       eb ce                   jmp    ffffffff815cb571 <=
test_mthread_victim+0x91>
+	}
+	ffffffff815cb5a3:       e8 d8 86 f1 00          call   ffffffff824e3c80 <=
__stack_chk_fail>
+
+
+func_offset
+^^^^^^^^^^^
+
+The function begins at ffffffff815cb4e0. The *buf* array is initialized in=
 a loop.
+The instruction storing values into the array is at ffffffff815cb520, and =
the
+first instruction after the loop is at ffffffff815cb52c.
+
+Because KStackWatch uses *kprobe.post_handler*, the watchpoint can be
+set right after ffffffff815cb520. However, this will cause false positive
+because the watchpoint is active before buf[8] is assigned.
+
+An alternative is to place the watchpoint at ffffffff815cb52c, right
+after the loop. This avoids false positives but leaves a small window
+for false negatives.
+
+In this document, ffffffff815cb52c is chosen for cleaner logs. If false
+negatives are suspected, repeat the test to catch the corruption.
+
+The required offset is calculated from the function start:
+
+*func_offset* is 0x4c (ffffffff815cb52c - ffffffff815cb4e0).
+
+sp_offset
+^^^^^^^^^^^
+
+From the disassembly, the buf array is at the top of the stack,
+meaning buf =3D=3D rsp. Therefore, buf[8] sits at rsp + 8 * sizeof(ulong) =
=3D
+rsp + 64. Thus, *sp_offset* is 64.
+
+Other parameters
+~~~~~~~~~~~~~~~~~~
+
+* *depth* is 0, as test_mthread_victim is not recursive
+* *max_watch* is 0 to use all available hwbps
+* *watch_len* is 8, the size of a ulong on x86_64
+
+Parameters with a value of 0 can be omitted as defaults.
+
+Configure the watch:
+
+.. code-block:: bash
+
+	echo "fn=3Dtest_mthread_victim fo=3D0x4c so=3D64 wl=3D8" > /sys/kernel/de=
bug/kstackwatch/config
+
+Now rerun the test:
+
+.. code-block:: bash
+
+	echo test3 >/sys/kernel/debug/kstackwatch/test
+
+The dmesg log shows:
+
+.. code-block:: text
+
+	[    7.607074] kstackwatch: =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D KStackWatch: C=
aught stack corruption =3D=3D=3D=3D=3D=3D=3D
+	[    7.607077] kstackwatch: config fn=3Dtest_mthread_victim fo=3D0x4c so=
=3D64 wl=3D8
+	[    7.607080] CPU: 2 UID: 0 PID: 347 Comm: corrupting Not tainted 6.17.0=
-rc7-00022-g90270f3db80a-dirty #509 PREEMPT(voluntary)
+	[    7.607083] Call Trace:
+	[    7.607084]  <#DB>
+	[    7.607085]  dump_stack_lvl+0x66/0xa0
+	[    7.607091]  ksw_watch_handler.part.0+0x2b/0x60
+	[    7.607094]  ksw_watch_handler+0xba/0xd0
+	[    7.607095]  ? test_mthread_corrupting+0x48/0xd0
+	[    7.607097]  ? kthread+0x10d/0x210
+	[    7.607099]  ? ret_from_fork+0x187/0x1e0
+	[    7.607102]  ? ret_from_fork_asm+0x1a/0x30
+	[    7.607105]  __perf_event_overflow+0x154/0x570
+	[    7.607108]  perf_bp_event+0xb4/0xc0
+	[    7.607112]  ? look_up_lock_class+0x59/0x150
+	[    7.607115]  hw_breakpoint_exceptions_notify+0xf7/0x110
+	[    7.607117]  notifier_call_chain+0x44/0x110
+	[    7.607119]  atomic_notifier_call_chain+0x5f/0x110
+	[    7.607121]  notify_die+0x4c/0xb0
+	[    7.607123]  exc_debug_kernel+0xaf/0x170
+	[    7.607126]  asm_exc_debug+0x1e/0x40
+	[    7.607127] RIP: 0010:test_mthread_corrupting+0x48/0xd0
+	[    7.607129] Code: c7 80 0a 24 83 e8 48 f1 f1 00 48 85 c0 74 dd eb 30 b=
b 00 00 00 00 eb 59 48 63 c2 48 c1 e0 03 48 03 03 be cd ab cd ab 48 89 30 <=
83> c2 01 b8 20 00 00 00 29 c8 39 d0 7f e0 48 8d 7b 10 e8 d1 86 d4
+	[    7.607130] RSP: 0018:ffffc90000acfee0 EFLAGS: 00000286
+	[    7.607132] RAX: ffffc90000a13de8 RBX: ffff888102d57580 RCX: 000000000=
0000008
+	[    7.607132] RDX: 0000000000000008 RSI: 00000000abcdabcd RDI: ffffc9000=
0acfe00
+	[    7.607133] RBP: ffff8881085bc800 R08: 0000000000000001 R09: 000000000=
0000000
+	[    7.607133] R10: 0000000000000001 R11: 0000000000000000 R12: ffff88810=
5398000
+	[    7.607134] R13: ffff8881085bc800 R14: ffffffff815cb660 R15: 000000000=
0000000
+	[    7.607134]  ? __pfx_test_mthread_corrupting+0x10/0x10
+	[    7.607137]  </#DB>
+	[    7.607138]  <TASK>
+	[    7.607138]  kthread+0x10d/0x210
+	[    7.607140]  ? __pfx_kthread+0x10/0x10
+	[    7.607141]  ret_from_fork+0x187/0x1e0
+	[    7.607143]  ? __pfx_kthread+0x10/0x10
+	[    7.607144]  ret_from_fork_asm+0x1a/0x30
+	[    7.607147]  </TASK>
+	[    7.607147] kstackwatch: =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D KStackWatch End =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
+	[    7.807082] kstackwatch_test: victim[0][11]: unhappy buf[8]=3D0xabcdab=
cd
+
+The line ``RIP: 0010:test_mthread_corrupting+0x48/0xd0`` shows the exact
+location where the corruption occurred. Now that the ``corrupting()`` func=
tion has
+been identified, it is straightforward to trace back to ``buggy()`` and fi=
x the bug.
+
+
+More usage examples and corruption scenarios are provided in
+``kstackwatch_test.sh`` and ``mm/kstackwatch/test.c``.
+
+Limitations
+=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
+
+* Limited by available hardware breakpoints
+* Only one function can be watched at a time
+* Canary search limited to 128 * sizeof(ulong) from the current stack
+  pointer. This is sufficient for most cases, but has three limitations:
+
+  - If the stack frame is larger, the search may fail.
+  - If the function does not have a canary, the search may fail.
+  - If stack memory occasionally contains the same value as the canary,
+    it may be incorrectly matched.
+
+  In these cases, the user can provide the canary location using
+  ``sp_offset``, or treat any memory in the function prologue
+  as the canary.
--=20
2.43.0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0251110163634.3686676-27-wangjinchao600%40gmail.com.
