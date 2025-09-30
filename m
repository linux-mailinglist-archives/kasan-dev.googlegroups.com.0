Return-Path: <kasan-dev+bncBD53XBUFWQDBBZ4I5XDAMGQE2CH2FSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13a.google.com (mail-yx1-xb13a.google.com [IPv6:2607:f8b0:4864:20::b13a])
	by mail.lfdr.de (Postfix) with ESMTPS id EB6C4BAB0FC
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:46:01 +0200 (CEST)
Received: by mail-yx1-xb13a.google.com with SMTP id 956f58d0204a3-63807df7926sf3027904d50.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:46:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200360; cv=pass;
        d=google.com; s=arc-20240605;
        b=askJG64jrH4m7qQhxr8WbVf9wRwflDIBa28KB13m/yG8iuHlAYX83nJdzVSAnVapae
         dVNBWWCv3wtf/La4ZJ5KJAHkr+12EigZPkeU/1MRJmo3G0u5EWE0H/VIxqr7ZZqbIrYN
         z5NI2j/TWcoCHrYBudwolycj3h1t7rS/3zUlYQRR3T4RLUI+CJJv3TqWOuCSsIBgUe89
         mpU0sIle7jIb+3tsjKqmMr4BxZy70JI7QssyG4rCIg6zrmWkL1aVS2yj+1T2TH3oBNf7
         eN78sMrzXXNUayJ1tzpSyd3AO5hHYVnzr51qq8+c4O755NkDvv630/71J1NHBx3FtpXB
         8kVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=JqrJnbH0MfGTmzlMHcAnaKnPxwDzmpkA5WiZzCYbE4M=;
        fh=dBRK0FFR4pfttPNGcW06DtcuR+C2a4XqBRhlYjV/0Do=;
        b=Ry3ECLlvd6f300PjTCjCJL172g/1qLwT4hCYkBk8MGqWZDnFTenH853GrJMeQ3hJw9
         LtvHnMmaFtm02ktz1kJhj+efU4518xya0DR693IoyYJ04sR976LBdSeA9CtzLTc8gX0a
         CXvy98yQiTDlhJFYOyUuSMRyZPwoWb7VcGY/puC4XNMI5tZ/PinHJ3jxB9MDOLK+O7Qz
         zOlDAZUPW0foFnrDRIQmPa+HvHaaqMBNVVMfuBt6dafQyEwiAA9Y4in25Z01S63pNUL+
         5lGplhyn0Xc5tfieNJX4KJET7vIXfoGzJgIu264I6k1/mu80hhhmObxsv9tWLBSMERo9
         b4TA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="EX/nRhw5";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200360; x=1759805160; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JqrJnbH0MfGTmzlMHcAnaKnPxwDzmpkA5WiZzCYbE4M=;
        b=cuXFMs7I9SGQ9C6CYMoz9FdkNHNziq3KlqiyrDklun3H16VdA+/nwT7N9oPNAUTz1S
         A0XAhFVPlFBPUPAswC9rMK5XpwLIin77FPA8ooHIMRdyfMK9nDOKH/dk5snVHSvlKBoU
         8FQAVfwujcKB5YNZDz9xo3nfH0BHb2Hpm+6cFVMARH9ouzEvCEa14WgVb7ztQuV9e6gR
         utPv57UNexadS9O7ludfVik8vRcg6wo0KmO4I31cVljg+UGVutbPy5yqMtMHPipDChIL
         zbkoaMQe5FPzthKXjbrlpba8dQyGjvhmd4yCxQ4d14O9qIyDPoiHfnsN8F83F5T6Jqcf
         pcDw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200360; x=1759805160; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=JqrJnbH0MfGTmzlMHcAnaKnPxwDzmpkA5WiZzCYbE4M=;
        b=XoBxxA5UQHpfAmguzE/ouQYGGvrpBRfshtLTnxPEZJ+r71u5C7CTr448SD7NKU/4lV
         uJL/lYrLQiwKE8Nsc6/b1B4WJ9QP9bXFPAz84UivgRYeCu/mva9XLlVRAx9/hWQgxpYz
         xy43MUqAeAYl3o12mmtd9rOowur3Na/UbNzJlrQfMP/cBbHis7DiaIOXRigALZuTCdS8
         oPW1kY3/jqOKXVr68dfpXKJuEfSPa2x1wYzQizEObgUqXQQJHKRlQ/EGC1ZLYxIEnpHH
         x2VSQH+1mUBL9WhPtTMLA1QXlW1jCQhlMvN1hITd1EwOLQ97tgb1mna3dIzHDAnfxtPN
         SRnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200360; x=1759805160;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JqrJnbH0MfGTmzlMHcAnaKnPxwDzmpkA5WiZzCYbE4M=;
        b=TEsZ+JNHSmI19j0GGR7Ca4txRE90lP6Ay8IFiItodtaCGC+bputGMZRDMSpPl2C92V
         hIia4GDD7rX5ke+xQXjgBc+uv1XkkIkk5ZH8iFdi8pQkftVWokacX8QHetTcd/i21JmX
         TwrJRamY3PYK9eQr2TftLjaZfKxw/MNgx1LsIbnzoGDamQwf+SYQ0UPL45Ih+yNF7w52
         JMBOJZUmGU/MOryTxKWGOlUJAHQQSOs2O3375ZUoc1elKS6LZP0d0IoyTMW6Bp7Tc7p7
         j6rMfVxxJTWzfFgITyGUZs3N0rVkKtwxZQVb2RvZyzkysVl10c1Bk9E1kJ8lhSVLBO9y
         aIMw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUpxcJQCsSS6FL63TUE4HyZCifGBc0/s/f9Uf+KyfB401RnjJwnbbmoDiFPxj9XoDVnX4zXRg==@lfdr.de
X-Gm-Message-State: AOJu0Yx7wWEOgmsMOxc7tolyGnSg06ExjV2d3Nhu4IF/i1Svo6BrEUiJ
	h9iuDdEKlMg6y56nHokCVy1Hc2goujTDF7uWtmJ2jtIdRK/cSQzD1wbT
X-Google-Smtp-Source: AGHT+IGmshbxwLQaTJNJH8zNWNCzY5ZB6bdsVZEK2sMDSlRgg0FuY9aGhGpvmHFqezz6ysvZJwRpTQ==
X-Received: by 2002:a53:8651:0:b0:636:d286:4832 with SMTP id 956f58d0204a3-636d2864eaamr17636920d50.20.1759200360228;
        Mon, 29 Sep 2025 19:46:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7dA+9nRy3wK+d+BfieCSCtqOCjr5/6kbFX7kKJ6wv2Ww=="
Received: by 2002:a05:690e:240a:b0:636:53a:b5f5 with SMTP id
 956f58d0204a3-6361b3baef1ls4363017d50.0.-pod-prod-05-us; Mon, 29 Sep 2025
 19:45:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVckbSdi7P2SW5CvbqTQ+7dg+fMhrMLNXuHkGuos9+eRTFSJmURcLyre3srq+6PZm9dA54+8PNctjU=@googlegroups.com
X-Received: by 2002:a05:690c:61c6:b0:76d:5713:7d65 with SMTP id 00721157ae682-76d5713902cmr152949287b3.43.1759200359430;
        Mon, 29 Sep 2025 19:45:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200359; cv=none;
        d=google.com; s=arc-20240605;
        b=OwgVUnC37WAbC4rP1XyaHA2LZZAV23jZuE3LsYgALHa9BXLlFDRpmC3F4OEhdo+5yd
         PvOazE1QNPQkvBT32QJUMvlbj4GnFOM4nQcmznUA8+DT8RADR2jeZSO35GXcoLCo/qXd
         zEsg8SXAx8dBItS7YbzY9X8Dj9gPKC0nuhnaHTbN37npwGGRuNuAFivGpCBjmFUhKjY0
         qOKvvmfo2+kdBi9MVaxsv392qSw6SUcvkK5pP0qpzafOmIP0k1qpd2F34fy3Zuoo6VHk
         GaTeo4A9Sl8b4nDWbbvxmsNDoX0546bLxz7efaKiZzPI4KRiPYN+wxHIRKnp7gpmspFB
         U+vQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wSXL/rVpDaFhkpWTVL2v5h6JspYJZAfxl9VpOD0Az0s=;
        fh=WRMNew7adAQZwxjA7PqKZN2SiWPCth8eC1paikd5NWk=;
        b=HeWQMqK6WmEzb5MfkbjRDz4LtQWi0i+2lMjeZX4jhHAohzVtrhuO4W/QSk1M0GDj26
         8S4KJ9R3dpZzJytOC3bU8fq+6ri7UTGWHO7mx2F5cFpGnoQqPlITIYgZlI8baHxZfAVh
         7se0H/kyIt2JVUQg7NlPVNwHS8UBrMmfCmq2pGbBAZJwfGAZ0uCYSL5otJf0vfJ7meFX
         Jn4qxP3qkirRCXWewC/erBDfFPDSsG3Pd/RaUECKXqMyyOnmCaFvq+bsA/1FFnaX2hSs
         I6dOHmTZlOPXxo/ZMgVmgksmb7rwSEoqYGrKnIEXQVK1PNRoOJTZbofYM+QJa4AUSLnE
         9Djg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="EX/nRhw5";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-6361e7ea5f3si755944d50.1.2025.09.29.19.45.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:45:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-b5506b28c98so3706238a12.1
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:45:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWYO0L6MMBGO9jV9sPvEAVkZK1RYUlbU6INo8e9V07nJgpizkLIPyWuQ4nrX9orG9jRcC1sL5/PP04=@googlegroups.com
X-Gm-Gg: ASbGnct+2RBdMFqDWJn/ABqWi5pj4VBdmemVK7vtXp0Nl8WYhx9QQRj13ojdE/kb46f
	Qvj9uk+7bkxEdR9wWJ/oshky0KFYtLct59gk7jYgLyXEQsjmbJ90Y0bdfrfH3g/5/BXxJoLEyZN
	3mZUawTkUXMuQOQwGt3H9MUJmM/3s/l6K8sbVq4x6C57JR3wiw7MfZrrdEdlMhv9VaJaVFBc0lD
	COloM8SIUK7vVIQs1YbzuLGBibDsdQ95zegzoSd6eib9kYonAAW8AskxfHM4MMtZ3VRd3Xd5lXa
	U9grUXvs3rLoTUMc+GN7JgwcfBytlpenwuNudVIUoBez/oW9dap0eHNOKIrWzN10y461rYd4tx6
	hydUY2exy0MrFCtFVjkWwdFhElBRdpUT8kG4DJAKT3UZ+JgBRUYTjMjb0GUmcUaDqMg==
X-Received: by 2002:a17:903:19f0:b0:26c:e270:6dad with SMTP id d9443c01a7336-27ed4ae51c6mr173137795ad.60.1759200358349;
        Mon, 29 Sep 2025 19:45:58 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27ed69ba58csm144532905ad.121.2025.09.29.19.45.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:45:57 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
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
Subject: [PATCH v6 20/23] mm/ksw: add multi-thread corruption test cases
Date: Tue, 30 Sep 2025 10:43:41 +0800
Message-ID: <20250930024402.1043776-21-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="EX/nRhw5";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

These tests share a common structure and are grouped together.

- buggy():
  exposes the stack address to corrupting(); may omit waiting
- corrupting():
  reads the exposed pointer and modifies memory;
  if buggy() omits waiting, victim()'s buffer is corrupted
- victim():
  initializes a local buffer and later verifies it;
  reports an error if the buffer was unexpectedly modified

buggy() and victim() run in worker() thread, with similar stack frame sizes
to simplify testing. By adjusting fence_size in corrupting(), the test can
trigger either silent corruption or overflow across threads.

- Test 3: one worker, 20 loops, silent corruption
- Test 4: 20 workers, one loop each, silent corruption
- Test 5: one worker, one loop, overflow corruption

Test 4 also exercises multiple watchpoint instances.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/test.c | 186 +++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 185 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index 203fff4bec92..2952efcc7738 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -20,6 +20,20 @@ static struct dentry *test_file;
 #define BUFFER_SIZE 32
 #define MAX_DEPTH 6
 
+struct work_node {
+	ulong *ptr;
+	u64 start_ns;
+	struct completion done;
+	struct list_head list;
+};
+
+static DECLARE_COMPLETION(work_res);
+static DEFINE_MUTEX(work_mutex);
+static LIST_HEAD(work_list);
+
+static int global_fence_size;
+static int global_loop_count;
+
 static void test_watch_fire(void)
 {
 	u64 buffer[BUFFER_SIZE] = { 0 };
@@ -62,6 +76,164 @@ static void test_recursive_depth(int depth)
 	pr_info("exit of %s depth:%d\n", __func__, depth);
 }
 
+static struct work_node *test_mthread_buggy(int thread_id, int seq_id)
+{
+	ulong buf[BUFFER_SIZE];
+	struct work_node *node;
+	bool trigger;
+
+	node = kmalloc(sizeof(*node), GFP_KERNEL);
+	if (!node)
+		return NULL;
+
+	init_completion(&node->done);
+	node->ptr = buf;
+	node->start_ns = ktime_get_ns();
+	mutex_lock(&work_mutex);
+	list_add(&node->list, &work_list);
+	mutex_unlock(&work_mutex);
+	complete(&work_res);
+
+	trigger = (get_random_u32() % 100) < 10;
+	if (trigger)
+		return node; /* let the caller handle cleanup */
+
+	wait_for_completion(&node->done);
+	kfree(node);
+	return NULL;
+}
+
+#define CORRUPTING_MINIOR_WAIT_NS (100000)
+#define VICTIM_MINIOR_WAIT_NS (300000)
+
+static inline void silent_wait_us(u64 start_ns, u64 min_wait_us)
+{
+	u64 diff_ns, remain_us;
+
+	diff_ns = ktime_get_ns() - start_ns;
+	if (diff_ns < min_wait_us * 1000ULL) {
+		remain_us = min_wait_us - (diff_ns >> 10);
+		usleep_range(remain_us, remain_us + 200);
+	}
+}
+
+static void test_mthread_victim(int thread_id, int seq_id, u64 start_ns)
+{
+	ulong buf[BUFFER_SIZE];
+
+	for (int j = 0; j < BUFFER_SIZE; j++)
+		buf[j] = 0xdeadbeef + seq_id;
+	if (start_ns)
+		silent_wait_us(start_ns, VICTIM_MINIOR_WAIT_NS);
+
+	for (int j = 0; j < BUFFER_SIZE; j++) {
+		if (buf[j] != (0xdeadbeef + seq_id)) {
+			pr_warn("victim[%d][%d]: unhappy buf[%d]=0x%lx\n",
+				thread_id, seq_id, j, buf[j]);
+			return;
+		}
+	}
+
+	pr_info("victim[%d][%d]: happy\n", thread_id, seq_id);
+}
+
+static int test_mthread_corrupting(void *data)
+{
+	struct work_node *node;
+	int fence_size;
+
+	while (!kthread_should_stop()) {
+		if (!wait_for_completion_timeout(&work_res, HZ))
+			continue;
+		while (true) {
+			mutex_lock(&work_mutex);
+			node = list_first_entry_or_null(&work_list,
+							struct work_node, list);
+			if (node)
+				list_del(&node->list);
+			mutex_unlock(&work_mutex);
+
+			if (!node)
+				break; /* no more nodes, exit inner loop */
+			silent_wait_us(node->start_ns,
+				       CORRUPTING_MINIOR_WAIT_NS);
+
+			fence_size = READ_ONCE(global_fence_size);
+			for (int i = fence_size; i < BUFFER_SIZE - fence_size;
+			     i++)
+				node->ptr[i] = 0xabcdabcd;
+
+			complete(&node->done);
+		}
+	}
+
+	return 0;
+}
+
+static int test_mthread_worker(void *data)
+{
+	int thread_id = (long)data;
+	int loop_count;
+	struct work_node *node;
+
+	loop_count = READ_ONCE(global_loop_count);
+
+	for (int i = 0; i < loop_count; i++) {
+		node = test_mthread_buggy(thread_id, i);
+
+		if (node)
+			test_mthread_victim(thread_id, i, node->start_ns);
+		else
+			test_mthread_victim(thread_id, i, 0);
+		if (node) {
+			wait_for_completion(&node->done);
+			kfree(node);
+		}
+	}
+	return 0;
+}
+
+static void test_mthread_case(int num_workers, int loop_count, int fence_size)
+{
+	static struct task_struct *corrupting;
+	static struct task_struct **workers;
+
+	WRITE_ONCE(global_loop_count, loop_count);
+	WRITE_ONCE(global_fence_size, fence_size);
+
+	init_completion(&work_res);
+	workers = kmalloc_array(num_workers, sizeof(void *), GFP_KERNEL);
+	memset(workers, 0, sizeof(struct task_struct *) * num_workers);
+
+	corrupting = kthread_run(test_mthread_corrupting, NULL, "corrupting");
+	if (IS_ERR(corrupting)) {
+		pr_err("failed to create corrupting thread\n");
+		return;
+	}
+
+	for (ulong i = 0; i < num_workers; i++) {
+		workers[i] = kthread_run(test_mthread_worker, (void *)i,
+					 "worker_%ld", i);
+		if (IS_ERR(workers[i])) {
+			pr_err("failto create worker thread %ld", i);
+			workers[i] = NULL;
+		}
+	}
+
+	for (ulong i = 0; i < num_workers; i++) {
+		if (workers[i] && workers[i]->__state != TASK_DEAD) {
+			usleep_range(1000, 2000);
+			i--;
+		}
+	}
+	kfree(workers);
+
+	if (corrupting && !IS_ERR(corrupting)) {
+		kthread_stop(corrupting);
+		corrupting = NULL;
+	}
+}
+
 static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 				size_t count, loff_t *pos)
 {
@@ -90,6 +262,15 @@ static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 		case 2:
 			test_recursive_depth(0);
 			break;
+		case 3:
+			test_mthread_case(1, 20, BUFFER_SIZE / 4);
+			break;
+		case 4:
+			test_mthread_case(20, 1, BUFFER_SIZE / 4);
+			break;
+		case 5:
+			test_mthread_case(1, 1, -3);
+			break;
 		default:
 			pr_err("Unknown test number %d\n", test_num);
 			return -EINVAL;
@@ -112,7 +293,10 @@ static ssize_t test_dbgfs_read(struct file *file, char __user *buffer,
 		"echo test{i} > /sys/kernel/debug/kstackwatch/test\n"
 		" test0 - test watch fire\n"
 		" test1 - test canary overflow\n"
-		" test2 - test recursive func\n";
+		" test2 - test recursive func\n"
+		" test3 - test silent corruption\n"
+		" test4 - test multiple silent corruption\n"
+		" test5 - test prologue corruption\n";
 
 	return simple_read_from_buffer(buffer, count, ppos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-21-wangjinchao600%40gmail.com.
