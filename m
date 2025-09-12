Return-Path: <kasan-dev+bncBD53XBUFWQDBBTXER7DAMGQERCQQTWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 299F7B54902
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:13:36 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-71ffd145fa9sf41467506d6.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:13:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757672015; cv=pass;
        d=google.com; s=arc-20240605;
        b=UbvVWU+EMAotZpXAEq2an5zmF0PzM6/UHz3ngw9KW0wEAh44jt26Q2xljlfMvGrrBP
         3LTdl8ozf/oGl6vWYIc+/aYZbwB8UoIkmG61P7RE/aRyDPMGDOA+iiP2aVaxnAb8BOII
         xKzNwzcKXI2nUUVzWF+aGJg/ppsgYsPUgj7wdGtNS5vxEcSG8ru6beHCnyI8HXQbq+OV
         TD0YUuyWb8Jgyv+//LHTfj6kQFJVgKPaBkmwc+QQCfo3ahANsic5CAEhaaDTQqLna3NR
         GYMDlPGTjyNTdrAZCztWAops++9uBIh8wb9SvLGE8F5jo7VoEkAJFtE0hc5gdzzO5uG4
         IJ/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=948hI4WlC0+VlGSzcxyKYia2kOciKVo2bDLTQzSZW70=;
        fh=7JkORL6vFYK1pDKApySLGghRdIx88/ZAKmWW81+aWoY=;
        b=HQlJyRBM0qsa3rQrt0hFtqR5RwgQstz6s9UGGMljSf7WrT4FuAjCrODZUA8PLMrRiE
         0X2T9HQ3XUEfW614KdCT4Lzm/1nYFYq2i5BzEgW7Yqf3jHTjDJ6v86cA2m/F0/ph2eSI
         zFFcXK3jSdElFQogqheuXtezxlwtE04G5mFtcxGoI/bFgtM6JA7uL0cLqD7MGd6OVUXz
         FbzcjNeVfgNB/t9/WNVWK0GwiVEmf7QuzC8jDmVCOm7OZbBVD5jkHSK2FTFSL0gFYWJQ
         /tGXLrbWDzDrBzjOFSWIGh53N/ZOoctLbN10rMXzAtO9yTZ3jiX9b2Dpun7N7WKBIfxZ
         ZLNg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JMixOptO;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757672015; x=1758276815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=948hI4WlC0+VlGSzcxyKYia2kOciKVo2bDLTQzSZW70=;
        b=pHbsXGD97nFyd2wQ5Dr7c80va/Ixlse/puicTC5e6K398wglIDGLgts1YwxOpLTIhB
         PO1Po38FSQMe/NXFsXuONJ5CEc7x7Ty7Gzn1hKf9nHHN8A45L9nA4UR1dCQ6+hAF+FCr
         PrjLsHWhMCrs01d+dRaAKS3/UrEX5pdBjgvCz70L4uHnFr8qFu0OijGwTjzxjJO5rY5Q
         1UX9iE0ua1j9ybuGqqaQq7E0zdCYj+8OMd72YaWLuSbWscIMI/VN+5MK4cIYNDaL8Xit
         wRadcOk1Xf4mRObGFRQ3BrWL+xdSGMigJ1D7QptLdQWqrh0a37/8COIxte6CM1T1+0Kb
         DuKg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757672015; x=1758276815; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=948hI4WlC0+VlGSzcxyKYia2kOciKVo2bDLTQzSZW70=;
        b=N4Yn5vJUI7NRb8UiquD/bgL1jk9kEPoRgr+R4SpbJ5Cj71FXslTwSNXMEdBX25vXqL
         53yOWpz0JAYkiO7BpJTTcltJAa0hh6DBUbPAuQ4sI/FDhLuEaf9WJQo/bJXjF3pS+pSA
         zOwp6Q1XPuI4J5zMAnpP9LrUlo3msYbLRx4QYEjSxY5Mvr0gKBEBR0bXZV/uErcj/x5g
         ViKhiL2OJg0rLq8rAxaPH+higQOjXhCp7qsCPsygOCoQM8LqRcs0d7gQcf5R/eNysdU1
         1dFQQMi2cWM49FlIBOnwYoT2eA/9qvNO88SA8FDpJqXRWiwAzW7GfvajKCEUBFs5qxSr
         0SMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757672015; x=1758276815;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=948hI4WlC0+VlGSzcxyKYia2kOciKVo2bDLTQzSZW70=;
        b=Ihpe1vVjvBSX0yBd8RIRy4tVqDLFAtSJgP+2qwovMhJBHjTrBmw/SBeHWt7B7ZIMLn
         uCSkCrOwRmbtqguhmj8E2NbPK9rPPgs8j5A6luA+qJj700BeAjwCPCHf91tvtwc1X6fZ
         RLnB7iyLkmSTGhtgIuCWASQ8nc8XL8mqzfdcDvLLDW8wLO+sMDjdpbEllgMDQgDrOaGH
         ZEmQqmWrUmmbPVoqATqqO2YSlkG2gwoD1a7/nSymwMxijrJpfNDUstFpC7FCh65aZX3a
         p2PtRT1fDrCWRfTA14yXbFWe9Jt7OJBqGenO/7Ig3P6HT82Qg1PiYTfP5oWB9w/TmQlR
         6p0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWm7ymmIcDLZhtxd1qhWJzEYdPnPns/NuSMucH8cspyqB8LpxWzY6pW4jGokQt6ldPwazTxKw==@lfdr.de
X-Gm-Message-State: AOJu0Yy9hdqDoCRhnVYgwrrLgmmQQM6pJ7iZvcoaPNPKltcO1+TWh6uY
	YpIAm8+ssZRq60K/dNbH9kqu8YH1EK6KZo9PtxGVMThNwMNN7NfjGUak
X-Google-Smtp-Source: AGHT+IHIJ8DwyiInL9f21dvs/SSdoUAWO9m2OuKkf7xXrYP8M4tUpvHhEeXqQDy+f8ZsHDXXnHyACw==
X-Received: by 2002:a05:6214:1d24:b0:70d:fa79:baf0 with SMTP id 6a1803df08f44-767c1f71e51mr29054516d6.38.1757672014889;
        Fri, 12 Sep 2025 03:13:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6dJauyT700pzpU0VLZHOGDfSscQy4tbLGYLSCkeIC0HQ==
Received: by 2002:a05:6214:4113:b0:72c:74b2:94c9 with SMTP id
 6a1803df08f44-762e590fcebls31138736d6.2.-pod-prod-04-us; Fri, 12 Sep 2025
 03:13:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX15I2AhY5cPJ0oImNNtyTlEW7A/pavcTfq217Amn/icE+B7p1D/T2uGfeRR9Mf7wHl8UIEddf0yxg=@googlegroups.com
X-Received: by 2002:a05:6214:5004:b0:725:f1c3:2ab with SMTP id 6a1803df08f44-767c1f71efcmr26771656d6.43.1757672014017;
        Fri, 12 Sep 2025 03:13:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757672014; cv=none;
        d=google.com; s=arc-20240605;
        b=aAIdQAuj3k2Bc9lyNWUrwaGQFJUhcMe/nofCt97AyA8WOpGFPmqdXLNKaziqdQBW+W
         w7E+1Q1mR6ifNg9Ip4Y3/1x9HgcDczyp561NVnAMuoASIXknredCAFqnQKeCjLjPxFxg
         AauJIekE47jTNMKTojyVjlEoVoDzOe+o4JfB1Qc2wBnNWwunv9fWFNnrYE6/dvThcpgg
         1NS4Bj0zvZYj235BFKlCl+xoi1laI5NSCTbzenf+cq1wAJ6RoaqbaHV//A+wvl5Lp8Jy
         b5csnReJiNsUW30t7B9BFVDFv7eoL2q3irAmjRzZGTxK/M3hnmLiEAwIP7SG59lOMf91
         S+Lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pqWZ4PXPvcwGUSVpTO1OvKWC6TpQO7QLp3apqR6W4A4=;
        fh=3ph2AllcfnIiqyr/GQPtUnGrzx3t2EJMcvo0LtAUr9M=;
        b=QvqNnVXtQEWrryFNknv0kvBxc4g7vVVdiCKIwHeI5S9tLplBooz27MNmpIzavZBuL8
         qW9CVtC/BNcgbkxWbqQqwipBopmQ8PLVEr8X6PjLUZv5lgtegNBYmvruXZYnO0HFSqxW
         dSMFiypMLmBhLyxQm+lgoKCd33x0kzfLgTBkPz6B2P2B1u6ZoecdvbWVPjLizTU1vpK+
         d9rZKkrOPZfCEVC/xpGGoqvbx64TGKTZ5X8XlXZ9uZgwj5cYhWTH+Dp01GZrokEAYUJb
         QwfOfXne0Yk71sOjBIC30c6gOPYi2mlQing7Ti5csqsZZ4DiWCcy2vRcinsrCJUVof9a
         oFyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JMixOptO;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-763bb0257edsi1600276d6.6.2025.09.12.03.13.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:13:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-77619f3f41aso202647b3a.2
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:13:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW6IMzG92qGCx5bdY4o9ZpsZjZCxoenklzUUSsyU3HBCOVdWKd36DIH7ltqS7k+0h7y7bp8AfywhO4=@googlegroups.com
X-Gm-Gg: ASbGncs4KtH8AqIlZgEKJfQLxDxbP3Z7DQO9Ubjz+ZTgYC85dLpvsCIxabMsMDqj6Nm
	rjc1+oNHD8azpKP9HrE4wRpnjMnKmuZ34beot5QXAPH1kVZD7iu1HywuZ0AkRmOKBrjg7zrRxTp
	yx6Vtu8sNwdB/5TLsqjI6pPEjwj3TwLS+XBbxBRZaAKHrH7BLoDSPanMGrcYykrv4rAediRd7+2
	uKmWaTxPwSEkuA0uPhRmHpyvwKh0qA3OcbQAA1RT2+iQotySEkt+XrpyAC/5fNzBE+eosWLisdv
	MBxAoHNF+XD/mYm+2it8NlhwpGwKabvPJOoo0IVHLtgqhXkYE1x6sAybVf8+xYbedTWMAOJbtAH
	I0ABxEqC3SUufwlPGpcTQ7qTEVZNSiSPUbb0=
X-Received: by 2002:a17:903:37c4:b0:248:811e:f86c with SMTP id d9443c01a7336-25d26663209mr26113005ad.34.1757672012838;
        Fri, 12 Sep 2025 03:13:32 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25c3ad33e1esm44309995ad.105.2025.09.12.03.13.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:13:32 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Mel Gorman <mgorman@suse.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Kees Cook <kees@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Rong Xu <xur@google.com>,
	Naveen N Rao <naveen@kernel.org>,
	David Kaplan <david.kaplan@amd.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Nam Cao <namcao@linutronix.de>,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	linux-trace-kernel@vger.kernel.org
Cc: Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v4 19/21] tools/ksw: add test script
Date: Fri, 12 Sep 2025 18:11:29 +0800
Message-ID: <20250912101145.465708-20-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JMixOptO;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide a shell script to trigger test cases.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 tools/kstackwatch/kstackwatch_test.sh | 40 +++++++++++++++++++++++++++
 1 file changed, 40 insertions(+)
 create mode 100755 tools/kstackwatch/kstackwatch_test.sh

diff --git a/tools/kstackwatch/kstackwatch_test.sh b/tools/kstackwatch/kstackwatch_test.sh
new file mode 100755
index 000000000000..61e171439ab6
--- /dev/null
+++ b/tools/kstackwatch/kstackwatch_test.sh
@@ -0,0 +1,40 @@
+#!/bin/bash
+# SPDX-License-Identifier: GPL-2.0
+
+echo "IMPORTANT: Before running, make sure you have updated the offset values!"
+
+usage() {
+	echo "Usage: $0 [0-3]"
+	echo "  0  - Canary Write Test"
+	echo "  1  - Canary Overflow Test"
+	echo "  2  - Silent Corruption Test"
+	echo "  3  - Recursive Corruption Test"
+}
+
+run_test() {
+	local test_num=$1
+	case "$test_num" in
+	0) echo "canary_test_write+0x19" >/proc/kstackwatch
+	   echo "test0" >/proc/kstackwatch_test ;;
+	1) echo "canary_test_overflow+0x1a" >/proc/kstackwatch
+	   echo "test1" >/proc/kstackwatch_test ;;
+	2) echo "silent_corruption_victim+0x32 0:8" >/proc/kstackwatch
+	   echo "test2" >/proc/kstackwatch_test ;;
+	3) echo "recursive_corruption_test+0x21+3 0:8" >/proc/kstackwatch
+	   echo "test3" >/proc/kstackwatch_test ;;
+	*) usage
+	   exit 1 ;;
+	esac
+	# Reset watch after test
+	echo >/proc/kstackwatch
+}
+
+# Check root and module
+[ "$EUID" -ne 0 ] && echo "Run as root" && exit 1
+for f in /proc/kstackwatch /proc/kstackwatch_test; do
+	[ ! -f "$f" ] && echo "$f not found" && exit 1
+done
+
+# Run
+[ -z "$1" ] && { usage; exit 0; }
+run_test "$1"
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-20-wangjinchao600%40gmail.com.
