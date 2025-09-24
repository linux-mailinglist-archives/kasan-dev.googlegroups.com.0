Return-Path: <kasan-dev+bncBD53XBUFWQDBB752Z7DAMGQE7OWCU6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 15C2FB99B8C
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 14:01:05 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-4257626a814sf58007425ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 05:01:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758715264; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z84X2XxMqyXMfG/AOE88K/0GTo9CC/QG+V4dFpPnXEOYtscMFVra6t4bEIJ8DxbgkQ
         2f1ntPc08PxxBDYa1H/t0Y8jRC4YO54czDMYRzTTKvU1YyLaRbV3a1yQNZ/zOI2X0FgH
         YkGuWFbwGG68dvbxNK4Brzqys7f0YMDpVlQJ1LiMZX17btaQ4jKobAOwgPRlCtRLLIPJ
         CHeDl79aHWSaFCm/GS+Jjqy93lziiZ5a26kDuZWqaNPXNmahfodDTlqc8ioRylHpCfTk
         brB+khKr8q37J32XNledv32T0MBZ1WAqTPGgyln2XikFbJoSFsnAU1DLHJePdgCtcZBb
         RshA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ie+1JaGDRjmq+u9e7xFvhLLxp9LEA1+7kpjkrJ8+dXs=;
        fh=n0Jw1nLQxIXp5nPxTq3LGmOinaKbojdcaG/n4mHOVsk=;
        b=fVtJ1rPf5Lb1G+L0PaHzj+gv3NzS9Htc+6Osj6RHJdvMkw5y8pYb+4ViVA268rQ2KN
         Zt38iibeDP2Vtcou8avNFtHIJrR1pOlawJgB8TcMEMe13V1gGUZpHBSHDNRQ6uqVAOGa
         ohEd3IfC/B/Z1kK51FWB4ZNoOykWOKUxbfF6g79DYAa+C/PsztI/kbmQ6nPEJjcEdsL9
         3/u6sQD54IKGiBYKK0dvxAubh8mOKP5Uk2xHokGaaabRUrYL4523TQfSocmxwkBvu6Xl
         nQjmu5iwvirue99uD1gNeyksf/pgop4PacfT0iGKq+wbwW6XEm77eT5B87cBRV1FmcIX
         lXiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TBnHomBJ;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758715264; x=1759320064; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ie+1JaGDRjmq+u9e7xFvhLLxp9LEA1+7kpjkrJ8+dXs=;
        b=YA82JxRMeNSXwLPCqQrVMsMRqFC8v+1DJiAjKCsdR6pKPJEbh71edK5kZVCtR9+Hyj
         FuZ96YEPA+5/Jw8l/FIF4sLjox5VEyhFmhrKOTI6s9ML4lW/UC18QZSgsdCvlZLtpnc7
         hYtv+cwhhNZGBoqPXCodz8h+F4GVllG+8we/Kjl4EcC1oiO4GvnDGIY+wTpiIJcreBxX
         apdUFmiPiTv/XPaFmxDgTVkbfHfpqGVX5njWjagrh2XJQo3T52vfyeDUdtKARfi1LyEx
         +YHyCJOU5GFyEJSB3xyKJgT/y+ANRy5gLMQSDjp+62WME9yeZN+tngoEdNzLuYMvjbQb
         /sjQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758715264; x=1759320064; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ie+1JaGDRjmq+u9e7xFvhLLxp9LEA1+7kpjkrJ8+dXs=;
        b=DCWAd8svu8zze+9fEuA392penvS570fN+X8HAb4LE7JxdVE07cPc/M5gtdBwJebL7J
         Ro/MH5mvvXunGA3r8n5Pxe2G2hZeYVYja2mMWuqgG8rJS83ckXE2jwEU/Ec+hZWYtWp2
         bgxDQzUh45Lv1yxDoOSGI3Zf5TAkS/zpKHbwdgWlydpxSlN67WVk9XFQuPVMFRmHFy/R
         aRkwSU0Dpb7URfS83WT+f0S+TEufCYFQ5zWmx9VFXwvKC6WpEnldBeB7jB2aJau3KFBH
         TgR+Sc49/9vKr5OYK3ib4iDKACogOzH8Rf3XSsijGrQCnxeHaYwopSg8tzM76DYBbCli
         +Kkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758715264; x=1759320064;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ie+1JaGDRjmq+u9e7xFvhLLxp9LEA1+7kpjkrJ8+dXs=;
        b=wzg2kb4cGuLhXackD6IZjv7JFZ77IN/umQ1u9/3l91TxbsnsQxSpJQDR74khnsjQ8Y
         TseUJjbR9fgteS65/s1RA22fdpvKa3rmjLWbf46E8O7pHWPJ0DcIOH+ZijuYcaEtv1il
         FYVMiOCitDRm8olQPYo6kIRUeAP6YTztpr7Up0AE1w+8k7kd2z2fabXn3elTarXmc2cB
         QoTIy51ANQMe4bTebmigMtWG36RSUAmhyB3FY1/OH1HV04hbSQztvRmmGFqJGyaCbqA6
         10GPb9Wo+6KnExRVoEMNCeSQ3bFeGZN0fqmqGiZ65I8BffOoLWfBIusjFl0D65S9SBOF
         BGYQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUoQA/1ybdddarhVPJ0KS7WQtl6+/FZJlwF92FKEbr01OTU0HysGgeEZdXG1MbrWV18pA2+sA==@lfdr.de
X-Gm-Message-State: AOJu0YxXmYwOJ2gmPxAZh/9Rwx8RYtku3h5yb7y+V9JkxiYnJ19+4U4R
	xN30uex+0ga+CYcQARs8EBvLMAo8fqP4PdZSOrcQnqzw6z1Dc+4vJ5FU
X-Google-Smtp-Source: AGHT+IH4j7tuNXYMMcQZhm6cCk1wI1ox4OPXIoIqZa4CCj1g1v4yVQWfM8vZtsTwtk6CMih/0PxV7A==
X-Received: by 2002:a92:cda1:0:b0:425:715a:e6c8 with SMTP id e9e14a558f8ab-42581e371bdmr89561345ab.13.1758715263687;
        Wed, 24 Sep 2025 05:01:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4fIlH8R0/Wlxf7fzHLxqVv6Yr6fFuttksmTd/W4KiV5w==
Received: by 2002:a05:6e02:1905:b0:424:1289:9cca with SMTP id
 e9e14a558f8ab-4244d934662ls69820875ab.2.-pod-prod-03-us; Wed, 24 Sep 2025
 05:01:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV5qPQ1Jcpt016edCROVNuQZiOmtLrYFatpQfhLEGt1m2yUY0gyp7j1+0yHNm88jGTmJRnLPvZtdmQ=@googlegroups.com
X-Received: by 2002:a05:6e02:b27:b0:40b:db4:839b with SMTP id e9e14a558f8ab-42581e1285emr78420345ab.5.1758715262337;
        Wed, 24 Sep 2025 05:01:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758715262; cv=none;
        d=google.com; s=arc-20240605;
        b=Nnkttu4aeZK3exzhUibpjO9ExN6gvPB/nkBnrGiOPJLRtlfRByDw3H6cnzcGbkX5ip
         kwDfPVLODzNKHOgL3Mo1sxy9rMFFsrsR7K237mRzPZojTNHzm3xAoSRJx2HS1nsHYXIB
         2JwjfG0Dh+CclJNn1IXF+j2F6eNwzArw35J1ohrYJRnWSENYZs8YRbI6y909zD08ifeN
         HoDEps9mrvLARb0ZNADb7S8H9Ow4B5+ttT6/EDNNVY4pG+a5WlOUh0Sd+T3VrOBHHfDv
         zLY7s83mmUIo95zjFfwfq1F2XTEL4BztUr2QvA0S3qeQ86mhOaVp7f1YufMBRis5cpNa
         C+vQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6dXdR7Vr7GvNxroOAYy+aBhMqtIGh2YpUvjEzBf0MIg=;
        fh=5bOvKlaEA8v6Y2dVJ64lgE815cZkq8NB3BrK8UE8Rws=;
        b=cqHqOEpuOJtnRjc9owNS6WGbLPEWNQK7ToAAV6iIpxyg8j70JqOVYa2+dUP0bjSwuf
         DEaBCfcM4EB2bhegyIT6NYkNAQ5jV/FkQQYNaAxrHYE70kRUCLrzoZgdR+n5OB6A8dzl
         3B2SidarRCI9WibrzTQNXb03UvDrNMLvl6lDfHpP5fQ19STPiQNtkOatXBLK5HkG1fte
         M9au0NWP9x/QV9EP/Be0Dg3ERLWcS0Df0K27GNqVJYB6q4sHu60PjnF5ExXknobK1ZHG
         eQpJr+1+4BHN/xhN7pALezk9AZqv8yfsYyC70VbBDcdWZcAsABXLvUlkD4pjBLDb2540
         Re6w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TBnHomBJ;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4244aca860asi7496235ab.3.2025.09.24.05.01.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 05:01:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-27c369f8986so24467685ad.3
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 05:01:02 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVBFxJXmoZ5BrfsEvkAHuRjSfvCJeHfbawn7dBMEkaeXhd7dLBoX4i41zBmUIr9ch/4CWMmUWT4e9s=@googlegroups.com
X-Gm-Gg: ASbGncvYrkxUhgtrrhdkZI4Mx0gONb+/mwbxiEc8bwyMtkF9hfkCcd0Ljvbpee4hr4H
	uUlksBj7CbuxVpU6vEZHoa+Qy1tbd+2uOItU+aWrk6fz4yhm5jHNLLJe2TmlqUJxobWid4W6Op5
	MHxjosNKwOWDL4bcz68BxCiWCmqTE42tmTsBwbqligf52yw7fWDgc/IfgJLCpZG4daF0+0AxpNM
	3xztmMaAqRAFVeVMzqNDKgmpUmcp2ilPox56X1859/RlIhajyqpQp1bEhi0+GMpfsSRPEbHGkU8
	qAV7EVInRRaWixP+vYajIzdViazBOf1voSBLr6anqAaJtrPdNfRIL2baWkQrj7rcRvt07NxXDjr
	KoZmozPv+nwGa3KZ14m+QXdw=
X-Received: by 2002:a17:903:2450:b0:268:f83a:835a with SMTP id d9443c01a7336-27cc9a91248mr60333305ad.60.1758715261649;
        Wed, 24 Sep 2025 05:01:01 -0700 (PDT)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-26980053d25sm191276975ad.12.2025.09.24.05.00.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 05:01:01 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
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
Subject: [PATCH v5 23/23] MAINTAINERS: add entry for KStackWatch
Date: Wed, 24 Sep 2025 19:59:29 +0800
Message-ID: <20250924115931.197077-8-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115931.197077-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
 <20250924115931.197077-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=TBnHomBJ;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
index 520fb4e379a3..3d4811ff3631 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13362,6 +13362,14 @@ T:	git git://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115931.197077-8-wangjinchao600%40gmail.com.
