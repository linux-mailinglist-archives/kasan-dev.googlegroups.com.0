Return-Path: <kasan-dev+bncBD53XBUFWQDBBRE3QTDAMGQEH5IV6WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E9F3B50D6D
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:33:58 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-7724903b0edsf5232351b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:33:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757482436; cv=pass;
        d=google.com; s=arc-20240605;
        b=YLj6gK43q4SyMS7Yz68vbuJzwZ8/Fb0b5mFlQ9UwZpmD2TUcXAWx/cgDFz8rdnE7u3
         cFleHFD7B0R79uJZjBJr0F7xsoKU3eBPJ9m25x4hP1fa0e+X3NyqrEwikRAt/OXQUhIj
         Q7Gko9ZoWcvVJqnuFZvstymIxSjoaMDzgnvx2z/utD0XhOymOqKzl+RMDwJKBboI4ZYh
         KnhtrlmeAog2Ll+nvmTPT0G67WlxzM/6EOXjY/2OPaofTDvYGDmXKjhnlJNdgP52vE0f
         ABc0aIQRerfs7jq29O5RiJJjxloBSLJO7QQN7Dm8AqNziBlx1c/Wgxie96eu7KdJCwWV
         ZbDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=KD4kr/MPLF7BRm5k2DMHIsQwcbi9dIOfwGdbJbwfCeM=;
        fh=RXDMw24+wuZ+Ruk2VNi5ijifihRrSTCT/62bxIPz7/I=;
        b=OVzR1Rtr/a5tQAxb1Ad3+2Pbvx6LRqUemKZBH80ECQre5/rnSjB1HhGIoAIwekH2os
         AwhUSl/rpiCOClPcOhOXjwj6EujJ6s8D6xZnV95XAixm6etTJPdFHHFH+Ls06UuGkOpJ
         AqRjJebIaPf5unAgd4/9jZ+btc9x+ridl/sgW0d/V86HDkO94ZhJFy2ECw5zrO3vLums
         wDHDYwYQ3xNLyf1TZTEd1EqSUkE0BiyIs0lNpcfsxt+JvkErdOxRYssrlAuLwGYqMHjo
         EjR3V9FkpJI9DaciIykP0WCaSthNFY2cYyBJFnl9ecrC6bxanZ2IWOF5uF7oLeVZ99U/
         08bw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MbYPVTCl;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757482436; x=1758087236; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KD4kr/MPLF7BRm5k2DMHIsQwcbi9dIOfwGdbJbwfCeM=;
        b=tq49CIlH8VnZTWMZhHEwg80+HKz0CavScpOtGgKInRbrj/f6uyEY0CEs0ig2PnLTNi
         PMkDAxas3rGNLGzuGezpc+lWwxhGl3MQgPWXzxM0YLZfrHBVoa0KFQZt7W4OK/EH/lLD
         8tEFGrnzlVciyWlkbB3VH3ZJhEq9Q7VlnTDbjlr/nVssw62Am1Sk8RjyQN6/PS1nB10C
         7kSB6VpTOELQjJpnCpalWB5rZU8k/WriDwiw+2Fiefi6vY6RUsyofVfHk8EWZvBZ9aYP
         bB8VsD4pqcp/fRf28WkuJ1exi0j48wLCS/09vVrrW2TI7lqXK21MTTWP5cFMXNRu9W5y
         Mt1A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757482436; x=1758087236; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=KD4kr/MPLF7BRm5k2DMHIsQwcbi9dIOfwGdbJbwfCeM=;
        b=HRJ+SyhfAhWo1LJoEB/uW8txxV1R+GHSzhpJm2+eblO/yE2UT3FlL6NkY0TezQ+pNc
         LBjQpPkQXFGvlUrJcwb9bldFS60LHNTszOaDRpjygeF7oyqKoOQNh9RIixU/Xz+8pdbz
         YDG6kMcrjxTkb7376hxC+eTgIJsfaMXsfx8qFG9X4VBaTtOFD5KQqotimU+FgmKQW4YX
         RQwU2wTy7LWzdYUBw7IE5larQstXiZm3MQ9V+dqx7iVvjohQP6TYa5cbAtqoyKSPPkHm
         WkfJxv5YBSfrveruFFaB1AqBQeXn5xSdX5iZ5VtBwJBniNEuP6fgI3n2AQPbu2GAacGU
         oHng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757482436; x=1758087236;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KD4kr/MPLF7BRm5k2DMHIsQwcbi9dIOfwGdbJbwfCeM=;
        b=ejUlcXb0w8UGubtipLQtCvnyxflRVAfc21bG8luddibduedL60SfCGHC5WXnRUfiIX
         APEfwyfHDI58DsSnbK0bBp6udGsW7JAGY3MsK4/6RbVu9rbdc2ff/RyYYO3J06ePWzev
         rtszJr11D3SENQehXNmNsUHlGTyODOAlpW2i9/tAyT+5arFGTuuOpCgTOJHgqHVXXftU
         smwzpFgyWn5zUNIkOOq6NHCbE7Nw0LMhPRa1IaxKRE2aWUrTNejM6X4DOXjk/s+joHTD
         OlghEYi6ZaXTaXS/8p+kRhA+6hhvX0FortTP+YE3GDT+q9dnw1oQiHEEZqx2DsKDdmzt
         c7Gg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXgVGvbKbxKvMBYHaZbd/EJEAUpTBUSK53D3O9dhplnp4PeFpbnGYFj0ik01kQACHwNfog9Qw==@lfdr.de
X-Gm-Message-State: AOJu0Yy1NjKO1DMCGyN9pNxPTvzN6i7uhcTrFRswE70FktXio6kQ6USt
	u3NYM3lc/TtdTe3v2FrtdJvG8fbxkN0WKfkSppuND+8KezZEM/EwQgvg
X-Google-Smtp-Source: AGHT+IHFpGUrkl+CJ0Is70dfgjmpr7U5DiqcHPM72pCIU3BNFUAWVweNOGqIr8zyJQJKxNSjbdh5/g==
X-Received: by 2002:a05:6a00:995:b0:772:a60:6c04 with SMTP id d2e1a72fcca58-7742dc99ec0mr17551556b3a.2.1757482436497;
        Tue, 09 Sep 2025 22:33:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdLe58bJ9Lt2BgeQZJwQihql01p8M2XCHrpunfZ5NCdtQ==
Received: by 2002:a05:6a00:3cd3:b0:772:27f9:fd39 with SMTP id
 d2e1a72fcca58-7741f0bec03ls5421304b3a.2.-pod-prod-02-us; Tue, 09 Sep 2025
 22:33:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW26p0W2u5PjOrXka2C/yyx0gqqTp11yb/UolZw7NMhvjrCCj6wkyVkOVshZrMOkSk81wt58Fm+Acc=@googlegroups.com
X-Received: by 2002:a05:6a00:3986:b0:772:5404:45ef with SMTP id d2e1a72fcca58-7742de5cdd8mr20770394b3a.32.1757482434964;
        Tue, 09 Sep 2025 22:33:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757482434; cv=none;
        d=google.com; s=arc-20240605;
        b=CmQ+AMxT294+/y7BrY7NjNk/Dfur5Ho9ZtVYog0QETqtyZQe8FI+hB5AG4Ta1OsE1P
         cvEMuld3Bfci5kIC1MB5DurHHUo2qDjZWzGNg3FNUSRot9PFWZx34m2ejFIm2rZwNTBx
         9A9PFJMbL/mo/PTp0gmvtwYr9DnCS/7ayBYmXH0gbiwkVvPE17TrlJDfKxHCVGUBMJNH
         zU5axuFHUyQfhZjdz/Ho2XnnpVdKTm6FfpGg+AWfqp1JTb0SgbaeTFym8luDxHo9jowA
         w6FVukwUbBwveu+NVFEapvMdppPOqKkUWf3XBVHQWCDQwhfOvTY+7H+AtsAQsQ3zasI5
         MRwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pqWZ4PXPvcwGUSVpTO1OvKWC6TpQO7QLp3apqR6W4A4=;
        fh=6gq/XEoO9Djl+wIplbzaJxKFImKoGkLwLUB+qqMdv90=;
        b=jlVkQstp7hiqdcb+sSQinUcq2goNuPYJB96aPXdg0MV0LuA0rRp1uHnrDrE5EguMsW
         m9YMTmHNUfyxaghZBbCc4CkiQ8psSKFUapDMmdO/i36PGqqkLOhOMs7NUqdrW3US5f0U
         7grd2U4bUSfeemXAyvnPG/jTunu8aS/gJO81NtJdF+/i836wpRapz6nG3SVXu8vFeSTN
         q84O1DONRt560NvC+La1TiFyh4m83wGiRJZXbpugBT8qvHdXVo0AMS7/xKOHgUuCn90H
         PUVHLgQQSMCw9NiW5aOBgKXuxxVQSmnoy20QqevaJZR5MYeWBFFeSOMFRiTqjFEFWBkN
         NfOw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MbYPVTCl;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77246129c24si641949b3a.5.2025.09.09.22.33.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:33:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id d2e1a72fcca58-772843b6057so5340075b3a.3
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:33:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXXbZlPPfJE4Ag/bsMpM0uwg6o1NtW4jQPfdeEsyaWaDFMtceZMknIUoBpYp4hky2aLjcjUE3qeoKw=@googlegroups.com
X-Gm-Gg: ASbGncuSOZCoISPn3ktDXYNSzw8diJ11Ukrr1oTPnq0MUE02yGh7dMztd+CsIvBg6NN
	2znJv7l4hdzYMv8sDffNBglYNrtM9F8ILgDSYrNavsoKOzGvuLwlA4T1lTKBkm96FWmNzOc0JND
	E1CxIbnCbtS8g8xQU3KHi9RWsJLYdOpf+BmHQEe5VwOI46GxuCr6xNRFTnW0UaZ07Wokt4FRSBi
	73Pg6W6vERwTc5bbcYZq+K2jjEUL0Nu/uCu+JpLV+3OZg+1uKjGufyvo8RCb6MG0yq0upw2ryvm
	czciGC2J1KQU2nnDaf7rKuLVAj1bBI2m3U5E5bReiwo7rQgQsU4bBQWEgBpP8Rns5NnyxJiH2BW
	f2N+aYawg88AX3wETa1ufKGfc/DEx9yYv+xca9QNi0AkZb6PMd8ILw+vDBL9o
X-Received: by 2002:a05:6a21:339e:b0:24d:301a:79d0 with SMTP id adf61e73a8af0-25341e682eemr22538642637.38.1757482434425;
        Tue, 09 Sep 2025 22:33:54 -0700 (PDT)
Received: from localhost.localdomain ([45.8.220.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7746628ffbesm3870342b3a.66.2025.09.09.22.33.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:33:53 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	"Naveen N . Rao" <naveen@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-mm@kvack.org,
	linux-trace-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v3 18/19] tools/ksw: add test script
Date: Wed, 10 Sep 2025 13:31:16 +0800
Message-ID: <20250910053147.1152253-10-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910053147.1152253-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
 <20250910053147.1152253-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MbYPVTCl;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910053147.1152253-10-wangjinchao600%40gmail.com.
