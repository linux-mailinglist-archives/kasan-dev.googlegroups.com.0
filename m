Return-Path: <kasan-dev+bncBD53XBUFWQDBB7NJZDEAMGQEFZHXVVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 21528C48007
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:38:23 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-3c9bfdade9csf6387448fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:38:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792701; cv=pass;
        d=google.com; s=arc-20240605;
        b=R4gB9ZOdJaHDBVn67acq3qfsj6qaryv+etQmg8ID3saZIUQq1tFY/EyEx5njZLAOM5
         Byng15TZCs7bOCFIkaLbm8aDm81I66EEjGRx8H2GXnXd7X4v1iP2cm5oowMgt7EaerYQ
         hrMArEZbJEfA616gtpOJagclrgo4znVvKvOCaPHAZENX0giNmxiATcYVgNYrzyfrobV8
         jFmXiQOB3/1VrA2F2R76cIG/R0yvqlrGAu6kD2JjI25f/q1BuYPZjkh3MehVCRJDe0Va
         SldEFizgri+pplR0qjubDSuxXAKsYYR+gcR/JqvqJ+SIBx5dCsB9U3cIKJJjKPasOJ5u
         yxqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=QpRgxb9S/UnFhyM6dCiqWZ2Pus7S8XpXa09rgLZavK4=;
        fh=Q8PgmfLWoDdkoxzFeQVvG6JAAQMyLw1HYhYMY8sGWSY=;
        b=R7NdM2qJ6Fop7CoUA7SsAqaB7yUhQJsC7QV3/LIFlHf6UELRIOroeALQ5xdht081c7
         hOtxSxOlf4oNJHUwy/EUtS1bpiL+2g1DlvXfzFc0Qwb5hT4VGublLPKlattUqwfxlUVW
         cA5c4Bujkb79SdYSY/13eeBvcLLGo+kB/Hxqy3J6mAKf4j07ZE5+3icoTQcInqOp/Y7i
         K203rD+OVpCSflV5O8f+lI16cmb4cLYJaij6W6AjWfEWlNWwEZUXExWPDP8gJVy5urXb
         9V5lb6BmoeDricYKn2kiCiQQQYfwuWDH9dK4BE7GwoldQHhKqZNYoINRGGwfv9LWMrLw
         QqbQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RMVIt4mH;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792701; x=1763397501; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QpRgxb9S/UnFhyM6dCiqWZ2Pus7S8XpXa09rgLZavK4=;
        b=eGDqjk9FiQbTzM/uI72/FGDze6MRzsrXMUDiSCKo/NxbfBe4w6EllABbTjmKexPEIH
         i1yIHRhzpie8sC1Lp021Kz8Zmb/W49vT++xLbZYPgaDGzGABnmg+yiUTkEInRmsHUMt4
         g0EGtbnWsjZGUr+IqqLUeUMV667jGcfmXrrDzY1RKtKkiCAoFe9wNGA7fI9AOjHXgd6+
         gqT0tUF2I3HWU3vZ9obEt7zluegu8h9knVT+3XiFVVMA660+LY+LJvmiEGKxRS6iZ+V9
         7IfQxi9rJw1uYUPRwv4hSgpt0DS3Mtq0EXr07XKPgXTfsNUGOiYuDnqUnPbJ0YtBXlQV
         XxUg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792701; x=1763397501; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=QpRgxb9S/UnFhyM6dCiqWZ2Pus7S8XpXa09rgLZavK4=;
        b=N+y3SfgQc6EjcgAYboN9XI1M4RGbF9vQ5rRm5jy9AmJ+KfyTk/e0i/Du5ZRM4a9cBq
         cd46k7e9NfyRqWNimKpHZgkSow8zWW7sWZ02ls9mYg1ffdf47NT5KI1KMk7LE8khPsrC
         FfzLkGXwKWpUG0UXDmQIDBXN12CsH/Xh5MeLZKoFVrzaIBUXb/T87qoTDMFKGRMNpj5q
         smdDGW34EV/V4VjZ+O/4NRLs4ZZIzU8DuopGxaNHQI1MRIWE+4OWUpg4WYoH+L5xQ92e
         we7LxOA4w6jkAqsbxrei9PnX+jbdjkJ4yBuNIIFdsa3a4D2Xw7bCC6vx9+3dyaKMtmV0
         Tmkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792701; x=1763397501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QpRgxb9S/UnFhyM6dCiqWZ2Pus7S8XpXa09rgLZavK4=;
        b=r4labn+CNRn0ge5MRzWXsnJ1rSbSnPonTypk5bTDcvNTVURZ2VXxaUPiPm6fVZBbJ0
         YYJsRnDZt1Wk2suxF/W07L8Z7M37hSS19QcM18fk+kqWlYAiR3bbBSL743EGrIr8Y83T
         2d49Ior47VBjpqECqT5wdYisRE/bHmJnTTDKrsjJPPWdw36gp1PKMTnSau8BvrW4/i9O
         t6EFaoukLlh5565vFJAgUw5VRCqqDHSpFOG7oY0mOLA1IfLQs/7Zt2qpia//2sNDeWjP
         EDxiuzlrVViAoUw4oK8svK8AOdlVd8rGdVChwavh6BVG6Hhl+z3yDQ4nphzb7Ee5lJIG
         0AOg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX6RXUESvLgdFIieaC+vggNWfFXeGu7PSAPaRunN8QLMog7G9EfWwFpC3jDKMzleIcysDnsDw==@lfdr.de
X-Gm-Message-State: AOJu0YxLn/4VH35wXdY/mb7steRAoDz6ctfDmgkDmOOkZyEPfycjetyI
	8QFYfrYH9sPr5LlDLq3p8fmR5QU4iwKlSZvrrJQCcWB3eHAyzMoOblqP
X-Google-Smtp-Source: AGHT+IEwxyOCF8Faxx2/pUlnekSgOS1vFsTWhHWT+BBvsCzi7FxrsKr3BG3eZR6NuZqmGNNHI93n5Q==
X-Received: by 2002:a05:6870:d1ca:b0:3db:d9e3:a94a with SMTP id 586e51a60fabf-3e81567aa69mr10192fac.6.1762792701370;
        Mon, 10 Nov 2025 08:38:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YoCH6AU3STzgG9De4LQE8nATrKHZPeiCW90Lg0ZF86yQ=="
Received: by 2002:a05:6871:8914:b0:3e7:e63d:723c with SMTP id
 586e51a60fabf-3e7e63d738als843905fac.2.-pod-prod-00-us; Mon, 10 Nov 2025
 08:38:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUiFVwbc8PoDdc4i+wYuUssjlPAqVtwIJtZqmD8We0iaOd72RsNR7Y0vlC2M/GYVJX4acXzMi369To=@googlegroups.com
X-Received: by 2002:a05:6808:6903:b0:450:3379:3c5c with SMTP id 5614622812f47-450608343a4mr12005b6e.3.1762792700420;
        Mon, 10 Nov 2025 08:38:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792700; cv=none;
        d=google.com; s=arc-20240605;
        b=aORe/lM4XMyYAYprSB1Z1YCj7s6tZRhHnkTVUebtWIwMEOX0JZ8ym1APTSpz+24uAC
         wo1t8cGi/o+JGJSpRUkikEva/Bzeqvcpa54HMyeArS5G4PwVTR/V1yCgTNCmV/UCLpek
         tKgCQUgkmlKXWnvBhPI+CkGchqDjFMoWSUt2Em6rtQ/o7dwxciX01eBHUpQ3c7dvj4Qu
         JZ2AxqwmIF+VK1M6ymAwGXsvAtytxjEvzuFHmz3mLaQtmQsgNql+5lgs+IZ2VzxITO7f
         3bUCqWEJ2FNwOrfgt7JmoF/r+i9fD43WS4mrDso17IYwK3AKSqN6bkPJV1TVqMNfL4c7
         x6aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=Tu+j4Ql3fqr3I/4VuukNZy9fUe1HehKP0k0yDQPRfsM=;
        fh=GOLbyngka8S1prirah6HgICbtm71qaQsMRTxzaMDN58=;
        b=FoorN1v+0iA+7h9emFUGD7rzHBU8OiDHPr6B7E0kTiRPMNtt/PT1Y0j/10LQC9aAq/
         Q4GvWeZIhLa0Hso252NSMHDURpMUbdD5w51GXPh/SNqlfp1p7dZx5ojHZ5n2zH3wBEPC
         2nr+GnsTqBZNufpZXIK76Qa6qqcrtu4auXh0hv/PZ+dysI0MX2ozoOicwcPajn4oTFSB
         h5VXQ0MYFEhmjae/H2LyBOFa/Lqpw9Vp4An/JrZ8kR1lLeAhwZk7KmzViuUDBub0tGlm
         jFY8rQo5+sIrtlN5IwUXdvBPmbFkWv2NMCXUJ162FPvPuMMxzTVKN1+INpGHBWAP1EN2
         q0Iw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RMVIt4mH;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-450027bfff2si214964b6e.1.2025.11.10.08.38.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:38:20 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-7af603c06easo2976886b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:38:20 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUsj/X9vBKzNrfmsBZHHNBgQ5vY5gCgjiZDXyltui77W7uPG63MVxVwoQjlURs6sC7nvfSU49g17qw=@googlegroups.com
X-Gm-Gg: ASbGncu+wwPHaKmpw+OuPI47kNFRYuVwiKEKMd7/O5BpWddHYSfHMOi5pwfTQFni3t2
	H3G52nAI5oaAlHIINZPUyszMIuCWTpY+gKW2ItKUGvWz4/pj9ThWlmgcYmePwfGaDEf7zj6L03/
	V+4CZByhpD5G+dYGAOXlvdJB/A5KYDOveGVyIPdFtf3k2+5VXaMvP8npFY/dBqTrSrrkQk0CRyt
	cmYEM/BrAwZ0CcpQMYRaEFGEuJoyDRdXXXbzKP7/AuKB53pEux2mgmXd5PWBa/dATGRSTgnffol
	omci0PbQ3y6lJcfdB+1ZobbRUMB1L0EAWFgLaBeHzTGwnuPaFqy8VwhTz3Dao9rRcR5PiE5zGu4
	UC9Y/28WSFVc9gCJJ0d0qK/I07YfILmBolMZn1zesZZsJeAF/a4l/AlesmJn25jngVPW1gmXaD/
	K1rSDMDy3MkLbYKuUJk9cI/w==
X-Received: by 2002:a05:6a00:9510:b0:7aa:d1d4:bb7b with SMTP id d2e1a72fcca58-7b21a285a43mr11992599b3a.16.1762792699318;
        Mon, 10 Nov 2025 08:38:19 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7b0ccb5c823sm12295899b3a.62.2025.11.10.08.38.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:38:18 -0800 (PST)
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
Subject: [PATCH v8 22/27] mm/ksw: add stack overflow test
Date: Tue, 11 Nov 2025 00:36:17 +0800
Message-ID: <20251110163634.3686676-23-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RMVIt4mH;       spf=pass
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

Extend the test module with a new test case (test1) that intentionally
overflows a local u64 buffer to corrupt the stack canary.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>

show addr of buf and watch_addr of test case
---
 mm/kstackwatch/test.c | 22 +++++++++++++++++++++-
 1 file changed, 21 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index 2969564b1a00..b3f363d9e1e8 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -32,6 +32,22 @@ static void test_watch_fire(void)
 	pr_info("exit of %s\n", __func__);
 }
 
+static void test_canary_overflow(void)
+{
+	u64 buffer[BUFFER_SIZE];
+
+	pr_info("entry of %s\n", __func__);
+	ksw_watch_show();
+	pr_info("buf: 0x%px\n", buffer);
+
+	/* intentionally overflow */
+	for (int i = BUFFER_SIZE; i < BUFFER_SIZE + 10; i++)
+		buffer[i] = 0xdeadbeefdeadbeef;
+	barrier_data(buffer);
+
+	pr_info("exit of %s\n", __func__);
+}
+
 static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 				size_t count, loff_t *pos)
 {
@@ -54,6 +70,9 @@ static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 		case 0:
 			test_watch_fire();
 			break;
+		case 1:
+			test_canary_overflow();
+			break;
 		default:
 			pr_err("Unknown test number %d\n", test_num);
 			return -EINVAL;
@@ -74,7 +93,8 @@ static ssize_t test_dbgfs_read(struct file *file, char __user *buffer,
 		"============ usage ===============\n"
 		"Usage:\n"
 		"echo test{i} > /sys/kernel/debug/kstackwatch/test\n"
-		" test0 - test watch fire\n";
+		" test0 - test watch fire\n"
+		" test1 - test canary overflow\n";
 
 	return simple_read_from_buffer(buffer, count, ppos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-23-wangjinchao600%40gmail.com.
