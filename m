Return-Path: <kasan-dev+bncBD53XBUFWQDBBYNKT3DQMGQERWHXD3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id A7366BC8A3A
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:58:43 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-77fa2ee9cb6sf15368977b3.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:58:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007521; cv=pass;
        d=google.com; s=arc-20240605;
        b=jB+slWVuD6rR/fb3niObdslNtguOhCOCaCeo9QCvdhgdHpZRxcIogPig/KMHW/KcCq
         MWpDz91GYcULAMb9BpBunE9HGnMQiQKFGf/+5T5r4A1STG9bpOIXxcnqJwV5OI0rHbsv
         CrJcep/JIcsmZLolibRIkcu0giw4OUgI3vKGyTHO1BXgjS9n2kPPEo4xtS/32/TZ/2Vk
         H1NenClWCbd7uZIgWWrT+q+OpP5wKCRSX3pMoJVsi3JS+x8S2DHvj5I/FbsR6GoZ6pfZ
         uKIFhxiRw7RfDFsXCnJERcikVnIDkSDXuSEhhdxXoaJpyCgAAok89qLxp7CFjcwh/awF
         wvAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=QNL4hy6BJD6QXWdco36EmJpkKsqOqMPIhC67XQmqeKs=;
        fh=FztFacAzpBNtt0kj18IE809C2+aCBdJPRM0AxTKCz2c=;
        b=Ow5y+B7eiRREbUFaqofu41OSOs5KAsRvbm9Ps9v1AANqiQTgJ/TBYFBHwhBY60z8Yl
         djeFVabjQPoSZLZH98CC28Miwz2tRQqZ/xYqcqKRJUnXeMkWgO4JmfBGDMpx5NezASoA
         +5xyKXcS2xHaUu31lo6mMDLlNAMsZzrlWk1VKyhwT5SN7+1OCjntMG0//tRMadcJHt5e
         o/fnuOXlwbmYLsJyWzzX5OEtsBj4w3GSm8zeCFYi+AwQFig9A0UwfgV8FqHH4AkGzVfH
         D6IfPzZOhvuWD9smtsU8J1n/Cu624wG4ol/gqpNT5010t332N9SMXDfHv4E5fCxvEezb
         agBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CRqX7Z4m;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007521; x=1760612321; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QNL4hy6BJD6QXWdco36EmJpkKsqOqMPIhC67XQmqeKs=;
        b=HUYbH5xXayn/t3Cx8jbW0hijYQt2t9brdDmb2UwA3C67MMfpYlLKel9WKTCdLfhLmE
         LErhNvRBHw10UWb1hIisgEIj/nMq9GHh0gDzBkm3yRqx4CXHohXMSGQs8n7WtKFvWB0y
         9I1i7a+Ima4xtEvZ1G09IZsd0scdxdm+uZIrT2KDLvl9d1zYcYbfZDf+qN70V4EixpHO
         pq2WvIRQ76NXld+39Ei70HDMHCTO95RLakI/IGsEO+hoC/tQ42suB5aU2+vrqFdP7nlC
         EYPBj5utFauxbPx6BNS/fxfeMhWneojOXw1krPgxuGoqKoTKZZA8WUZ8uR7RhgJc8EMM
         Iieg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007521; x=1760612321; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=QNL4hy6BJD6QXWdco36EmJpkKsqOqMPIhC67XQmqeKs=;
        b=a7AArbAp6K4hI8QMq7LG113D+mIH98A5dtUIcdZ212emgoXZs5Jx0/Vm6y+hbRTFjL
         TOeVAP4yWif1ErTeEsc21FIpMEU5nvrOxs9uOJAM1QCT5a8DvtDeHOUyn24iNSQC5syW
         +PwYSTEUiMuv0iYZ5N5EIHW/Xx3zDqVwjO/2Z8ApHGwaHB5RvE8z11ufa75dM0UFFqn/
         VkhHHjlE25mrcSgcXl1Uc7xZELXzYI8pSNwRza5msetaNyqjVerdf55oyY4nUSrbCWeh
         wUgmS2/m4ptAqfEJJiiI0EkiC7OpPa6gREZxg4ySAD5l3D/DTSDTAuDAREsHqqRRdGUm
         EfLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007521; x=1760612321;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QNL4hy6BJD6QXWdco36EmJpkKsqOqMPIhC67XQmqeKs=;
        b=pRQ0JmDp1bFC65VlYEz+ENLNqyqGsyfgF2VDT/EL/s5TdWWF2UH/xbXywyJAV38FXx
         Q6f9qwI7iNLfsNOISF6+SD0wvEzgQMGKDD4etBj+ecNkLRvf7I/Xi+KOgrNCzFL3taKQ
         kp+q4Fa94qVSml7eMIXLmjzwHcdwSD1R8Da+7wmEmmXq1bELLCLEgN0I0gdEKNKqd9xU
         uFK0jYD+7/ZzQKfHz8Gya8DSsYY6AJIkxpV/hfaZ3TTCEaV0eKNpojFJEzNXxy5Ak0bD
         TrW0Nxic4bpO94IeBYZ+Wh/OzDMCLLCiu28jg4admGtQ+wQeU56IHV3J3oDDkrlPKNTT
         GEHw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUppqqTq44Or1WjqYdS5kM3LiLB6q/mNzgwM3tqdc9mlsLlJZtKkRgHuRGKY5+KHLBukPX1sQ==@lfdr.de
X-Gm-Message-State: AOJu0YzS6dmwAoptEcq4xEDZwpLk2kojSHiPtqPg6nqsyjVQifmhrGrJ
	g/Q+rjGNLYmI18uqHyyewfOD4LROIeLBV0VR+JPx9PZBe59R2Vf3xTJo
X-Google-Smtp-Source: AGHT+IGigaUgMs/9ovxgXDF11GCiMRQDBwIFl+xNLQXk08lX4DWTG/KcNn7iVI+rLKIp/naiMQoMpw==
X-Received: by 2002:a05:690c:d21:b0:77f:90dd:af46 with SMTP id 00721157ae682-780e151bd6fmr118090247b3.3.1760007521572;
        Thu, 09 Oct 2025 03:58:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd74sNkyXaPSGGJ3MoIVHBms+Q8JDuQfIWNsOM/OpjD+hw=="
Received: by 2002:a05:690e:4190:b0:63c:e5a4:5815 with SMTP id
 956f58d0204a3-63ce5a45ff2ls376291d50.1.-pod-prod-08-us; Thu, 09 Oct 2025
 03:58:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUxKxPThHHtHHA9dGBe5ZbKpHAzld5mk2gDVlsLY9GV+oxmSp8TucCDsb9zC3PFQ4W7q4x/F1mzWTQ=@googlegroups.com
X-Received: by 2002:a05:690c:316:b0:721:6b2e:a08a with SMTP id 00721157ae682-780e16d29f5mr128301007b3.37.1760007520680;
        Thu, 09 Oct 2025 03:58:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007520; cv=none;
        d=google.com; s=arc-20240605;
        b=jy13/rKETy9QkgD+F8bV7ZbrynsqgGShL8H3H853qXZJgOTQt90FKmrtDy5JfEh230
         EFs64nebCtioey5n4EleR3nbefrpb5G/GLokSnKWDLe0vdyxRfJsH9XBuPYv+0v5OKLm
         kLq4rawkKhNawWmQ2E1V3CTyx46MeNFDrbDbTseP5eVYYBVnZNa269yaNVCqRXhMygYv
         Ft9MBw2cx7E0erqnTrTZm9RYtSe0IABxjFghxBwxdjRGivEmGKIHl7/A0XR2f4Hvwrgo
         pyOiq6LfG+gIj5pN8lUYWAtRyDhiFjXmgOFOHgZ9RHMKMlKzvUW7jeuF7shLGs0SCyMA
         CDvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0ApAR8xSadwKhwismNq+uPz91ksCPHZtzxjh6qDdbHI=;
        fh=rzfI/62Uq45Hb8JoHDF0P1Vl4HaVxdkh+Ey7Pa1Lzco=;
        b=ixkdZuqVFI72tTecNQ3Vxht40B14j01Rnj0+skgLc3Fl71xpl5ARI/vcRm9+dCQSte
         8mPJYpIJhfIwqV+FAG2XMXfBFh2Xz56bUfEjADgYKGt+q16MPtMi2FLs53YNv93+7ptc
         Bsu8arVQNw4oiIlGAFdUosGgdFDozC3rEAyrLbEAap95NGGK5y5wQVB0SZCZ/69EoAgU
         WXqLvwaJVUtBw65taFv0V8Qbx2u4dSdW7ZiRIc3iymSnsXcxwnxwy9e6btFbR/gWtdgi
         0Izw/oSlzQ9lvzxsdldwb5aQ9g8Rwnxdtd6nHuW3EbUWh5ogyst+THrURYJFiJ5sggI8
         g9BQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CRqX7Z4m;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-63cd95287bdsi11537d50.1.2025.10.09.03.58.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:58:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-78125ed4052so1006118b3a.0
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:58:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUNqxIQ6/+CZSBMd8GwRnGGN5kLb8qzD3pKsVZf3k0aAZs6VrEm/M7XbchGao+e7V0dx29UqNxaO0U=@googlegroups.com
X-Gm-Gg: ASbGnctgQTOSk2yiaQMkfFapR2iaK0r0PN7ek2BZHVaEP8FPxfkIfZIjtZvJ+T33HHK
	04LtusfUyNuhHfU4dGwL4bCvwZ9/xkeGEx/Ph8o9Hrzshv0/ur88S+brCCpWa4awTFLxGrVRLTP
	nAgY8ScbqV6PumJaiDpj+jTLDsUZJQZSXFCjZ/9m2NhTwYvLHA8pJMYkPOzWJSr+Ep522RPNV/Y
	oycL2WgMO0q7ALzPRzSSDpdcGhloGwSp2PKc9yAwEQL7K4BkIVnLx6iS/k+GxdhXMxGamK2qQp+
	O9bREIdlpBaL2MmcYOP0yW65THEEuu7uA96T18B6RThPg+5EDaCKPW2hS5+CG8wcOTBTu/BUD6a
	RO3NxuykxZgAgjdz8dy4gAwUTBi3Y3L/kkWCQDuVGhIf/93ISIdjOqXGz+lbLhnoySkfNg0k=
X-Received: by 2002:a05:6a21:6d99:b0:262:1ae0:1994 with SMTP id adf61e73a8af0-32da845e6c6mr9710336637.42.1760007519707;
        Thu, 09 Oct 2025 03:58:39 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b6099d4d324sm21591393a12.27.2025.10.09.03.58.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:58:39 -0700 (PDT)
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
Subject: [PATCH v7 23/23] MAINTAINERS: add entry for KStackWatch
Date: Thu,  9 Oct 2025 18:55:59 +0800
Message-ID: <20251009105650.168917-24-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CRqX7Z4m;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
index 3a27901781c2..d5e3b984e709 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13596,6 +13596,14 @@ F:	Documentation/filesystems/smb/ksmbd.rst
 F:	fs/smb/common/
 F:	fs/smb/server/
 
+KERNEL STACK WATCH
+M:	Jinchao Wang <wangjinchao600@gmail.com>
+S:	Maintained
+F:	Documentation/dev-tools/kstackwatch.rst
+F:	include/linux/kstackwatch_types.h
+F:	mm/kstackwatch/
+F:	tools/kstackwatch/
+
 KERNEL UNIT TESTING FRAMEWORK (KUnit)
 M:	Brendan Higgins <brendan.higgins@linux.dev>
 M:	David Gow <davidgow@google.com>
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-24-wangjinchao600%40gmail.com.
