Return-Path: <kasan-dev+bncBD53XBUFWQDBBAVKZDEAMGQEHYXMIHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 99EBBC4800E
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:38:28 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-4337e902d2bsf12229505ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:38:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792707; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZDqw/PesxNU2abIx7Ev2rUxyQ6rXHoTHqn94SsDdxV7M9M/CwNLNHhXfumkStig30K
         ZRMR7ht7hftZ9iJ8aAeHg/SW0kYvXQa1UjtxzBAg6UPR4hvv4+R3DrkkZylucKyCdV7L
         m1P51kfnb7kl97c2TtJciuqw9NbUC8/I1Bv6c//hzUxaMtZU+Mj/UnrWUCAGSYVdbp9p
         OFsxCq8DVo+DpsppbY97zRlMTumpNkfKCk6MG+qQr/6ShXHZJRHR6VAIhsqWWexPENF2
         acLkbX4+bUDwE5+zkkzWzwGntHQd/whPK7B/p3pSXaUd3B7GHcuwK+RkbZcyAUL5AT8p
         njrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=W7GQ7ITIbRqSs1sByuqRvcjTW2M7SEVXNi07z1Cg50U=;
        fh=vGdxG8aVgxL+IDctGAjnwFioXGUZ5dQ/eFPUUnon2H0=;
        b=HVJxlcVjAWJeMLmeMbRrso81bk4OVBWkSkavnIJtUQPA8QaFIdczH3kv9lU92Y2Z62
         eXlMftcQqKjkoRpdjJ3frFX+4PAu/SNEVCi2f9P577jHhXLRpLsMrjlbHywvj5kh4qpD
         BnbKmGvh/SBYbjmfPPsQ9TbJNHuEdhEWL/di4kbwnW08JTT2HkZiudBI/wGYF9BM4+rw
         CgKzCxCr+2c1lum2yGi2tGwnf63f/HqgYMm3fiyJ2gRinqDC3MSNZKf4s5gozxZGoUpS
         VmbK3jypjj88+dKEuZKTREHTh9tlqwof/xpxa2sAMq/hZ4Lr3UrvPAykyn9WOeG2PKu+
         XFwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZgYIAhmx;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792707; x=1763397507; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=W7GQ7ITIbRqSs1sByuqRvcjTW2M7SEVXNi07z1Cg50U=;
        b=PjO6n4vo5BgFXtkGSxHc1C6AvnBBfDGFFbST03Uz68ObWUVjr6Nd0hXAkht+cdaTpb
         Oj9KB5Ov0pi6ae0y6Q8cltu/5S65Vq0/Hsmm29LR37Ic06rgb2EXgDszBO1pL+kvdZwM
         PeZzVQNM7LrpFnnuBBniqYd0eTaU9rmY04rHSlqKBLc2D0ir8C5HXDYI7AIXeB2Sq+pw
         BARvxAgcZZP0mjuDUqVtX1hVsKYoT/XVQ3JtcEF0fZBEMAArAGHEKCgjD0K/OttLzPx7
         15xz7JdJNH7XE2+YYWeewLPAN6SctFqC2YmalLUx91MNL/DoLCtFwGpvBDWW0o5zZGzT
         PW4A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792707; x=1763397507; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=W7GQ7ITIbRqSs1sByuqRvcjTW2M7SEVXNi07z1Cg50U=;
        b=A3IpfJNxPRwAn9ffRo5pyJv0qdtlQdrV2WgYrwOQy8OhnCeOVvLS2ehj+sHnaIj5HI
         y3OyDwu0VDBJfPLYiVVAt/pUC/IYifXlkt6k2xG0WHKC8jGLzMy/SYnaI2+4iffAB2xK
         GaO3pOyoodYIqmV1CnEWkWAvW0G0k/pQdzx3hTRM1hLYUuEVL+ELA+x8dZBC93a10kbC
         gwCB4YOyBloHW05VjHY9VPqazqdJf3/Jm8U2uIFUdRL+jXkD7zvHqY2mf/Sqa4TPtQhJ
         U8AEis0OKPvkUh8Vw3+ESgsQuGkTrvkhDfPUtn+KexS82Afk6jVjtkuinqFqYIO8j2T3
         57vA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792707; x=1763397507;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=W7GQ7ITIbRqSs1sByuqRvcjTW2M7SEVXNi07z1Cg50U=;
        b=NKq5oLIhrpEL1dQ3RBxzgZjPB73rEgNYbM/9/9zdUdQAvarxLGI4cDxYGYritmXad4
         AkSxz/N9cBx4AP6iWvQE7pQpmQ7/PvY1DvlY3EJ5vpx6Pxkh9v/SedkQj68CSdhUogTn
         l4s24IGi880spomrYChkEAeP74eQ8SJnBZf9uglm0qDjdhdNfATnTC6S2kYFxnDrPliE
         RCnEDoWnIUJMVZbKKMhE99JhcGCHRnK+H415IOt+xo2ZnTWMgM+f3gSGCvA2Q5Qb5IF4
         VWs8DddW2g/e0eU9Ncem3qBppyxN/FoY4KbDfKSdAdPu9TwcWx/VzvRD00oaT2LxUi2I
         blmA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWqXpAmpwX4fa7V2FgxL0M8yXC+pR3k4iF6Yeqyww4EfBg2AAHgZhnD8iGYyxbbV+yF6yOGBQ==@lfdr.de
X-Gm-Message-State: AOJu0YwCk5YdjNJmcBFqiXDCZ11Encs7IL/p0MH9pZRWLO+s8UtqDJ3/
	AXOW5UPyyhs7FSszhdkgJJWT7RhvYgwnilxChkE83R8B8242U54SmUil
X-Google-Smtp-Source: AGHT+IEjf4ymAmRpJl0CdMB2EXM6gcXex5ZCE8pbuglbR6TkqCUVimuVcAB0gLeD0vaZXExp6UTDmg==
X-Received: by 2002:a05:6e02:216d:b0:431:d864:366a with SMTP id e9e14a558f8ab-43367dda177mr130974965ab.2.1762792707020;
        Mon, 10 Nov 2025 08:38:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aoRqkkDTqI53KGrxlMAu3/LQWQsZHREwId+TrzbAnNsQ=="
Received: by 2002:a05:6e02:4803:b0:433:2b0c:2a3e with SMTP id
 e9e14a558f8ab-4334eed8255ls234755ab.0.-pod-prod-04-us; Mon, 10 Nov 2025
 08:38:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXxwbAiplgdsO4MCCCWPe3omwQC18J06PdYFLAr6PoxBJReMMJpku7Z6tFiRTg2Wo6wOpbGrRz5TE4=@googlegroups.com
X-Received: by 2002:a05:6602:3402:b0:945:a37e:660b with SMTP id ca18e2360f4ac-94895fc8cc4mr1200528239f.6.1762792706063;
        Mon, 10 Nov 2025 08:38:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792706; cv=none;
        d=google.com; s=arc-20240605;
        b=S28/cRncIisFWel3N8ac8RInha0vtfD0vieOXoxk9aSNPT1dp6+baF5GIyfUrUm8oS
         7wltW8YwdJ2KUHMvwJfH0ceCqyvKfh3VFO9Anok+kxJgywbHQDig3B4M1z/cWdM3c90j
         OOqRVri8F2UnmwET4Z6ZWAoUwVPKIE8cpiPXNfWChXQR8GU+Xoj8C3Wo3ZNt609aEjGJ
         evV7+eemoY78qcCeBSp/nlkvnj3afCH5pSfZbUX6A8ncNZ9moMBliLophmkARaVkGHtm
         cNx53GrHg/8MRHZpYTvmtq8zLANLeZYgDirpyer82VqrEBBUgbuuPo0GHUtrlTDb7TnA
         pfpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=OV6BMzpvIqPwW8tqyoqDeqegoFqswySAQs38qdvsWjQ=;
        fh=8mfnOelfgczbspYtOo46sx8BIW3g6L6rFfu+7H078Js=;
        b=RAkQt6fZvuhNdRrY56vCGVTe0cxDAL2k6t4iEB2pWbReSGYad3DAQ5QBQsimkRpYVv
         Rp16Zxm5Dxw5RkvNdUDPgeeWLyo8ty9fSgLc13lm/x6Od5bYWFj0lnypuED4dEIjsT/g
         D0a97MdMBKuimRKyMLYxtIcZrKXWID0RF/mJGl96fCIMWkKuRlbw55nalBGFhlL96kTM
         TVl5D/P0gunL3LlhPxG5SBUPs4J3DBRuMoBT1elplxjM/euxq6bXp2JgSLHy1T9QBqRM
         CmajBhzloYpubLwse+gTbxY28zrAOZuijwqT+9ryEWAs+m0xxgIZUDKnUUwEcTXyp7G0
         t79A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZgYIAhmx;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-94888bb8cfdsi57212039f.2.2025.11.10.08.38.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:38:26 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-7aad4823079so2903305b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:38:26 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVQVCy/NHioHHuGqZls98wfUczNmfsp3gUpZnNXO3GPg4w/LyYo/8MiTxWYCCOBZjvlykzY32+CyqM=@googlegroups.com
X-Gm-Gg: ASbGncsCNiE5L635fCdLz4lCPec7u2fPYqRbBTI7j5VC5gPyiPQez6qB1YjcjNm2Snz
	XKrSroC0EvdJcYXGlMm5+1091tc3Gr5Cg1gcFdquydKEK/jpbFxGdnx/7qAiZ+QI7FtEsfNsvg8
	jDL2AnT+SIO7aClsKvSezvZAVOuP0oWXn+6c015kE+SnphW4A8fYlx7vYd49QzioCsnZ64NLILX
	uVhPFk+DgF9mVSkP5nrQv2tLfnghg0UydkIMq5unGiqLdvhJzBA3H5erH/Mu0kU0Crde/+TSeCl
	/Tpp0klEzc6dBJw4BU0/pqcXk3/UlD32aQtPEN6V0bJ7WimphH4Xftq7UBBsDwbnBmMlIQwDzru
	wmm+vohBb2Km+TCV7hYQ8XpWS2UW5AiU9FWU7Y1jjdXjbCwAV/2auDcx2jJQlV4Jcbz0qwb6GLC
	CNkAUri2imuHDTOcKIZ0wcfg==
X-Received: by 2002:a05:6a00:883:b0:772:4319:e7ed with SMTP id d2e1a72fcca58-7b2277caeecmr11401444b3a.29.1762792705147;
        Mon, 10 Nov 2025 08:38:25 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7b0ccb5a31esm12324547b3a.63.2025.11.10.08.38.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:38:24 -0800 (PST)
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
Subject: [PATCH v8 23/27] mm/ksw: add recursive depth test
Date: Tue, 11 Nov 2025 00:36:18 +0800
Message-ID: <20251110163634.3686676-24-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZgYIAhmx;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Introduce a test that performs stack writes in recursive calls to exercise
stack watch at a specific recursion depth.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/test.c | 22 +++++++++++++++++++++-
 1 file changed, 21 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index b3f363d9e1e8..1d196f72faba 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -17,6 +17,7 @@
 static struct dentry *test_file;
 
 #define BUFFER_SIZE 32
+#define MAX_DEPTH 6
 
 static void test_watch_fire(void)
 {
@@ -48,6 +49,21 @@ static void test_canary_overflow(void)
 	pr_info("exit of %s\n", __func__);
 }
 
+static void test_recursive_depth(int depth)
+{
+	u64 buffer[BUFFER_SIZE];
+
+	pr_info("entry of %s depth:%d\n", __func__, depth);
+
+	if (depth < MAX_DEPTH)
+		test_recursive_depth(depth + 1);
+
+	buffer[0] = depth;
+	barrier_data(buffer);
+
+	pr_info("exit of %s depth:%d\n", __func__, depth);
+}
+
 static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 				size_t count, loff_t *pos)
 {
@@ -73,6 +89,9 @@ static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 		case 1:
 			test_canary_overflow();
 			break;
+		case 2:
+			test_recursive_depth(0);
+			break;
 		default:
 			pr_err("Unknown test number %d\n", test_num);
 			return -EINVAL;
@@ -94,7 +113,8 @@ static ssize_t test_dbgfs_read(struct file *file, char __user *buffer,
 		"Usage:\n"
 		"echo test{i} > /sys/kernel/debug/kstackwatch/test\n"
 		" test0 - test watch fire\n"
-		" test1 - test canary overflow\n";
+		" test1 - test canary overflow\n"
+		" test2 - test recursive func\n";
 
 	return simple_read_from_buffer(buffer, count, ppos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-24-wangjinchao600%40gmail.com.
