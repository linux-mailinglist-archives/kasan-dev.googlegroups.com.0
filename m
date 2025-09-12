Return-Path: <kasan-dev+bncBD53XBUFWQDBBWPER7DAMGQEQ6TJERY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D0A8B54906
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:13:47 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3f65be4978csf17795185ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:13:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757672026; cv=pass;
        d=google.com; s=arc-20240605;
        b=GRZu6tzRs1KAz/71k8G734+GWBjHzNLWo35LjtjmRJ784bp5h0ASdk5daoVoNEbGQo
         zMqgNsatDzjLuiVwq0B8tj3lgBuOfI1CDHhMngSIVfrT4PPj8bqv6UDG+KT88+Ex4NkG
         MSFwBmkIBXHAY/4+LABfuEf8JAoKJF/Ar80ZF+DZNcQa250bkXnTA+/Ta1gJO7YyZDlg
         A2wMOjayrQJH0FoNGxVMB5h1AmqFWx9nHdK3O43tF6P2qccY7dEsU+WVz3adLZylQdAs
         KmKax7iGJv4/sGujNEQMq4ZYT/vDVgr+32s3XJHb51wbf0PUSEoUI93zWK2deCPPxiKa
         0b+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=EsTJgOGMGcrJpPqkbQ6ENeIDyTTrCmjWymUBf3Goguo=;
        fh=WzTwqdSrKSqryqZKvhFoFrPX57D+XV4GOM56BdtwzkU=;
        b=APyUg5SX9EIcExwQVtt1SijorWGyBXyGU7ca1FPqAeYKx3XPKTJGNe6Qws08xIwWyF
         LsjnFYBa8kckNBaZYui0j2wUnfUNlxua90b3GYugUmNjbLi1FapK5R//WC/65WiDOHn/
         QSfWf9Fy3c9jZx1tWYbVi9R5SQMEKtJM+02ZdMmMsp+6exAT7eaZtEFIkE3pBvLrEKDp
         nAKH4fDAOn8M8Oi0yl+vI9kgv3ZhNXJp1iUF7mjLYDwnErvjP48Pcg1k6oXAD9ykuwpJ
         3y9A4rdeHpjgTnYWJ7QRjQcQRk+DZaKKtQ+oW5Sp7E6Wb93iEss96RA1SXVEUrB3mgNG
         rMsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Iib25t3E;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757672026; x=1758276826; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EsTJgOGMGcrJpPqkbQ6ENeIDyTTrCmjWymUBf3Goguo=;
        b=sr+vY5Qe1uqkydneNE3rFQPbXWeeW3opbvrE92qr/9heD4mZSUgbowxnGvhznVEudB
         eWmmSSmloQCqDhWjjhhqtJ2YDAov0Urem79whe7Xdvlsx02/pPRU0JbFKZBJS093SZXQ
         zs9emWYSLIeIRzZX+GWg91HfmBj2xdAGHnU7VLn6IofDTib7xZx6JkyHF8tZu9ItzL+B
         xj0L2G07hmfKB3QRrtf8utls96BrTA+BBWCQ4Hdmp6cm45RWXTBkJ4tH/gZr3E1UjXL5
         awKmCk6VmLrgJ8STuO7wEwo1DVAtcmyqtXsDCKTJzkTemSfa5SVxDIyjzRVJtMya67Fj
         +K8A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757672026; x=1758276826; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=EsTJgOGMGcrJpPqkbQ6ENeIDyTTrCmjWymUBf3Goguo=;
        b=OlALICySs6tg5ha7rEknoaqOGKAgmGQAZUsNIQGnf7kFgl8l3hUtIEV8hxQAVpHjtX
         nrpOjB/jJk0ppAXjhT1mbsmbUVc/FQO4wr8mAM1rau/DVAJhcKGACsJEgnQCd6OTigPD
         YbgBhT7ESj2z7kgnVy2K3QjwoImrpBXp91hElJbdixispaeDnmVTU48UzEZAaINrSwW4
         obNCdL6GnLbS6jfbQ3EXdLfm7EExehuqAYYrVU2pUVfIkSoI7fHZM+GpORiJm/tNwUT8
         jo0oer/O2px59mcr48lpftHU3ISFDRxjsIZaGsA6LTMKhRvbki4s6dw3FSqLxrj7mj8G
         J8ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757672026; x=1758276826;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EsTJgOGMGcrJpPqkbQ6ENeIDyTTrCmjWymUBf3Goguo=;
        b=pD0r21QSvJQR/oDin5FHzTckvHfTS1TVCeMsqzyzPl75rane/oazzUx8fn2e01uJEB
         x1rqr+s/kSH93pHpwEiesY4z9EdZfSRIAM8EyPKco0ODyDnNuZTvRYzzqa5q+r3+blwE
         /02uRusOClWXX0EmUDPpxlbWs0AT70BVFs4GXq8k/CCFvJTyVgvVYvY0mEYyyhDL1HKb
         oQUUXOaM9iHgRluYIuQtxnqAXdaDCCVPTzxOP/38mMvEl2NsVSr/SkHBQUpGAKiMuqfr
         +8+4+jlDWp3JywBSx3Iqu59oUE5MysLTAv76FRlXQadvjIScP2Uug22ISY5rqWxj5kdj
         NXJA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVeOWswta4AyplBA4SNqNBs4Ag3mIkbOyjXh90LR1fcqw1WqEJx9OjbB09ehT2ke5zd/Olvtg==@lfdr.de
X-Gm-Message-State: AOJu0YypN8osYeJXuLBfaMToXmfkXmcHHFaBhoT0jJ2ar2aWwj2h0kC8
	JBsUUB/MtDyxN/64cN74wkxq1FshClpoMgGjC4u6bQZsOMizmBngdySF
X-Google-Smtp-Source: AGHT+IGt1fzHSAoGLR+DpNhk7kibSmiNDJ0h0LnnUjdnsjajnOPUh8QbIDvPmJ0Dc1wPWotY2YzwZg==
X-Received: by 2002:a05:6e02:b2b:b0:418:8f31:d32e with SMTP id e9e14a558f8ab-4209577e9eemr37195615ab.0.1757672025706;
        Fri, 12 Sep 2025 03:13:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeAYrOg9srP1JohbuNXLiwXnT8j/YWn3PUuZR1jCh3/hw==
Received: by 2002:a05:6e02:248d:b0:416:6b0:a249 with SMTP id
 e9e14a558f8ab-41cd46a21a0ls15459775ab.2.-pod-prod-09-us; Fri, 12 Sep 2025
 03:13:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbKIrphlZoDmVoWzKCAnc+BCdbPjw23dgTVPHpwQxc01Lr+ycwrA2vLIbqqL+poyVT478k76gR+c0=@googlegroups.com
X-Received: by 2002:a05:6e02:1a8b:b0:41a:949e:316e with SMTP id e9e14a558f8ab-420a4bff03dmr35450835ab.24.1757672024765;
        Fri, 12 Sep 2025 03:13:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757672024; cv=none;
        d=google.com; s=arc-20240605;
        b=auswG3h5twT2SnJUxrh+RvY02JV7OPQfsy0vU9UdPyirWiel87OlqoowIjWh+W0WB/
         MUUm4xnTnmReWHnR9TXa9p36jTEIxPRZkqK6sH+R3LEdmAYNtZTUaRc5Zn6aY1Lj0dNH
         heSSWKZRA9rxgiNawJHXEfBhY29MNfcfW+KAh3gprz8afk/Hg4dJiyOSAY2rEscyr5kr
         k/Feud+igr1zkFlVut98PvWju65a3QXs9DuOO8CE7/6+isiZowkqEzX9jEkp1CGFxDOX
         2AGoRU07jZgJ45v/fbpFQbCyXYqKwg90TmLtNk2S6IOWsTu39BZjLgcYMY44ikbk9geV
         og5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=I55bZq7ZFzzpD1DxoyTRdsSYeFKQhRWPVd7TpHbtt7w=;
        fh=bJVIMdqBXEbbXe2e08D4WC0N8oZIEn2alq6ZXxR5m+w=;
        b=fNU4P8mHf5PLp6C/sWb3ublQqZqhw4Z1H4FyqvtQWzE4n0IJVcqaFufUQeT3U5Ctpq
         AQaTnmVzitZZioGz5ZjVNQJQGndwirt/L5Y0kKP7gTjqVBSjCAjWcQc+HgvlSa73kB50
         SN+rZ3RvjhklWnaMMd13ioAC4hgFoHHGfkmx3aJ+bxCYnzUOqSbydlgJ9HGHi9UKCBy2
         84xlailoBtjpGEsph56l8+FHWiVmeqE5RFn8wy3vBOSfqpxVTn1RC+NotOW2sjZ4lmX3
         GPVnhIkrQrzXO3wbWBrc2GJQrEXFGQB7EG8fVKZKfsENolEbsMm4QzYGA2GbFWT1VvYf
         x+Ig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Iib25t3E;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-41dee17d767si1574395ab.1.2025.09.12.03.13.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:13:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-7704f3c46ceso1607841b3a.2
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:13:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUomyocfWNRRUAzeXzc77NSc2to6U09McMgeI6AWecl/tVKD4qaN8EEnegt0ksV6PDlBTxiCO1BG7s=@googlegroups.com
X-Gm-Gg: ASbGncuAXJf6r+tUaraVMwNa52t6IUPOVkY5gIbBhmiGa+9GqpSap7eafGNyf7AS0GS
	JTp/f6V1Khwyvoit+JfWAwVrt1TR5eMUj57VrdCypbshRGTInjSU1DOR0g9p9BDu9tncDz9e2Gv
	jq/w/aWydrNI3NBeygKTreqIpkDstFTKmsScv81urhwDaJPNpD6k7sdzUyhkyoju4kzHz62Ly97
	5JFVGBkn9IYT74C9IAk0Vr1e9xOJZVa051ZQPOsT2elzxT+TFOgv6ADoGR2vUdJ3ewSzdAAJtOq
	HK5kXw0JASSPr6KE3zpvb7O6R4whr0FZ3Uz8/a85Vi4oYQk4tWrzx/tGZhePsQRdU1luyLTYbi+
	7e6wjWjyY8eqowV/Uim5vSiFjqGynRny2Ko39BoDqSzS0ow==
X-Received: by 2002:a05:6a20:734d:b0:24f:53e8:cca2 with SMTP id adf61e73a8af0-2602cf104d0mr2912224637.60.1757672023846;
        Fri, 12 Sep 2025 03:13:43 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b54a3aa0f8asm4307035a12.48.2025.09.12.03.13.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:13:43 -0700 (PDT)
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
Subject: [PATCH v4 21/21] MAINTAINERS: add entry for KStackWatch
Date: Fri, 12 Sep 2025 18:11:31 +0800
Message-ID: <20250912101145.465708-22-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Iib25t3E;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add a maintainer entry for Kernel Stack Watch.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 MAINTAINERS | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index cd7ff55b5d32..1baa989abf2d 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13355,6 +13355,14 @@ T:	git git://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git
 F:	Documentation/dev-tools/kselftest*
 F:	tools/testing/selftests/
 
+KERNEL STACK WATCH
+M:	Jinchao Wang <wangjinchao600@gmail.com>
+S:	Maintained
+F:	Documentation/dev-tools/kstackwatch.rst
+F:	include/linux/kstackwatch_types.h
+F:	mm/kstackwatch/
+F:	tools/kstackwatch/
+
 KERNEL SMB3 SERVER (KSMBD)
 M:	Namjae Jeon <linkinjeon@kernel.org>
 M:	Namjae Jeon <linkinjeon@samba.org>
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-22-wangjinchao600%40gmail.com.
