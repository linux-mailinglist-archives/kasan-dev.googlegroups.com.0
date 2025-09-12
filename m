Return-Path: <kasan-dev+bncBD53XBUFWQDBBNHER7DAMGQETTG2C3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 62C58B548F5
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:13:11 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-32145ecd7basf2720890fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:13:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671989; cv=pass;
        d=google.com; s=arc-20240605;
        b=Oe17ho98TkG+B824snEdfWrVzjSfxfITS0wIXAhhd+c6vzbCZIN5r1z/VzQ8sU8pGy
         A7QnJzpgf2U6vvqa5iZ74YUM9QTggHqS8cJCy8rFnbgMA91gJPfh8SG7Co2c/pExhe5F
         aSev0RJhpo1sNmy1330p2Vytonz9ZBt4z5XmOPiSO6NNRoOFwk5aJxTjNwGk7mKJfwB7
         dHBoGcmSPzq1pFlvqhUXEkGrGJRl0ePJwlpqanHFbvvLr4/lfw668UwKyGMaezGvMrYY
         Pem+nhew51tJ/BYPlDt4GCbmxJJvGV4v/uDk7fP8lV9Hxw73+JnikbKXGGbPMoJMYnY/
         s67Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=GDqr8HUXzy5I/gh338bUKg4lt75cmjSSS2yuwK8zTPU=;
        fh=70rX9hZejsS/Il1gi13e3IgBtjRVnWUKv2ct3K4Lyjo=;
        b=KSvOSnpdWlQ5YoxtBs3dg1zQwkOwkPSOlkeYV6DbhBuAWxvB2VxzDMErDDOGsbZgHA
         tj5DkZiW+V1p//RHyAEZdtqPeAWA5hEUNmP9Aerb719zqQv9edNht/La7HW7BWv4lrOX
         jKsOMX4gkbUZLGDGH1B6v+ZdpcUWbQ38fIOiYz6OLaI/3Lmt1SUBm0BEH0GOSYYuVyet
         xRdgwLut0Q5/SLHnSxTad+kI8ZC5ftL5wCFluw+um/mW+WwvuFp2SXg0Hl09ftbuTUYH
         vHET+WNVROcZmLgsZzC7BHODN3A0wc3+p8LykqN11IZAr8DnzUCeirk4J+MRi5tBSO4S
         jB4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=M3N4bFkc;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671989; x=1758276789; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GDqr8HUXzy5I/gh338bUKg4lt75cmjSSS2yuwK8zTPU=;
        b=I2lePgWVhEUiaJjCYRAaMav14nqxCb0RmVjxYd2tA5iinJ1VLRbAlEdHkCLZ/EP07i
         bCS2Lb6InwjpkspsfVIa8uW2Hp3wbWslGHrpE7WCo9FirPdsZpx5o48MkN+kBEQZ6ONc
         uKFJgVXyCcUI/FUjutf810SHdtMpXzutq7RfSU790Q8sOq45Ya/g/AaDCPgjKgPlmVfF
         Ju8nR0r9EaBZidOfq95jPfYyaIRezTmQJ/4aNMMsP6lEBq+dztJ6xHp2f6jbll+TFdGM
         65LIIagBqRkRf4MDH6y/5Seg0V9BHstMYKu6H2JZ27ahz2kcM+Iznm7ENFpNkWULDDMc
         Ejag==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671989; x=1758276789; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=GDqr8HUXzy5I/gh338bUKg4lt75cmjSSS2yuwK8zTPU=;
        b=d0BWUMDEjmTLyO8YFBgQw5XacGCVaROkLS1cjxhWrpd8cx8ARlE1vk2WOiKKU3wDUA
         kDX+P5Ae0vPMHbzqp04mOO9TXZ3ptYdzmxpxcEdyaJ/Q2SicvympyL3KErRQujnV0CP2
         F+37lIi7il70XZHSnD2BZ/KEp5odWuM2qV/BYFsnr8SsxeZmM+AkCsMKZwciB1F5Djre
         2hNtTZvY8J+fxMeNY6jCenTyz7CLtPQVE/+g38BO24pyVdNIxSJzItrXGjzNOnQyLqhM
         nu25TCPBG3veRTRx384SKdDPnp09Cw/Qcx21yTt0PYU6GcZchifcrJPITZL7Br7qjfpl
         qjTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671989; x=1758276789;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GDqr8HUXzy5I/gh338bUKg4lt75cmjSSS2yuwK8zTPU=;
        b=sShhSKx33niSJRZErGot6nhUtlRnu7EoiSwX6gDYhFOxrY5xK6nB8pPVZwfK+5+iQ0
         /z6dbk2meu681KpXO7UeTSYGX89att2Pfxsiei7cHnmrgMTWfCI8MpkguGMOiQ4imfiZ
         Vh3mbebJc2EMUpe+Eo4VijggAoKBm8RVNUPTjiJ0/cgVyssbc3Hswof4+Q+XrjhoyxG7
         MlYU+9k8o8zxdN72EX/Rb6osu7ZdMfM6rsmJLo3QlZc6ratUwPKW1AaZQtrSjpzhscBx
         bF9qg6L/egQjQR3a6qpqaBJwQL+n1BI7ieIVBW1tc27bXgu1OCIywpkqURTRUdjKx6Rk
         QE4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCULdZow2I1k6jb9/zQ+5kDxT7B5daBEJkd4EZxevcYT2fYC0IFLZV+DKLWFhY5Td17OhrW2eA==@lfdr.de
X-Gm-Message-State: AOJu0YwaFIQiBWCpeIP9K42twXOIqvhvvM13tJVYFVRtPm3shsaWlkep
	W15zGqEUNcWQIkefAhyja4GOQFbxBfsvEhjCVZabbFbHjHJQK6T/kbwc
X-Google-Smtp-Source: AGHT+IEY45T76agjc5UZ3IK6H4zPoaSAO3MeCXk4FVWPa4NToJWvK7ObIg/CMqW0DMFGBlJoCAh1Jg==
X-Received: by 2002:a05:6870:fba1:b0:319:cad9:c6e5 with SMTP id 586e51a60fabf-32e572ec2a8mr1083409fac.25.1757671988786;
        Fri, 12 Sep 2025 03:13:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6u9FIblOdNPElR7tzBhX4YO67aGiUc5uSrOKUCggJjFA==
Received: by 2002:a05:6871:260c:b0:30b:c2b3:2130 with SMTP id
 586e51a60fabf-32d06213b3als1593106fac.1.-pod-prod-05-us; Fri, 12 Sep 2025
 03:13:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU2ksBuDMYB864tXuxWI3sa943rEiUaXrp4Rw0v5NjE17I452AHoHd/IJKYe7tOZ85qN6VS8NIZ3F8=@googlegroups.com
X-Received: by 2002:a05:6808:191d:b0:439:ad1e:846b with SMTP id 5614622812f47-43b8d896121mr1021689b6e.7.1757671987996;
        Fri, 12 Sep 2025 03:13:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671987; cv=none;
        d=google.com; s=arc-20240605;
        b=Fp8jULzJTghB7Xobm+cIYckqWvInZD4Y4uohl3NqvE+1k4VFcqnkZA8aa0z03TtW//
         wEjT9kEXj/t2aJRNIqZWSL002lc3+wCF1m+KuqKTXku8DHjZQa4wxm0x0NEKLcRNPETz
         /ZbmQW7Xp5O5tQsF/UbWBuUe10xnSq+sbU31OG9NKndAgjSsowb19QSRCnYFhuihqSiH
         U6ShX0VT01Lmu3CFVhsPsvaAHi2zzGXDUr/z3WLqKxSSU42cvH5pwZlaSjjKfyXd0UC3
         iLxff0PgdYEbDbD4K5sL2V3UmiyiypVIb3oeQc07jZWWz5NjPO2ZUm85ECk73NSwbaMn
         DXhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=clh29CJb8P7VxnXXw4h/9gdA7sU+C9WtN5xBt8cm/X4=;
        fh=abMsjmKafVfzNuy5TAsKIru3XTYdAmJhfXEeQ8dLXlE=;
        b=X2yXBUk8T6YHlNCB9JsdujJF4dFU285R7jmmb1nLOgfDaAIX3mV0ReCyXmyDLaVMIE
         3saoDzF083liI70tjkQSZ72agsYBBKob0bRKMGlcGhhurK6eEWPh8msgTY0GbFDFcZPT
         pnTUeaJ6vzYMFZ7o+79VXFmHHKJXSPp05Y5ZBgS3K0+uuRRv71/P/p1MxMxTvlTNO/Fl
         FitxIxixA+YYc0xiEje8dnMKAzfh/89sGORsnwQwgu4E7xLDVErdwSMxvrCY7tZSCC2d
         f0/1XBw0inaMofkKtPqUpcEAJdeNjJ4BcL0BAmL/NkcLT5QRRhFG2PL5x87vbqjdOAEm
         mLhw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=M3N4bFkc;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-43b8dd21b7bsi63714b6e.4.2025.09.12.03.13.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:13:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-7722bcb989aso1243358b3a.1
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:13:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX5GlKF8NfI6xsfRMsZO1yv3mYn9cbUdqEKhmuI2tZgHHPyvIPU9C4/rywqlqjBmH7Y7B412UW6FpE=@googlegroups.com
X-Gm-Gg: ASbGncvhUMAi5462UWx+4DGvDsnrENIRzJxwBtF160IjDjtTmRxX/fPumGk9MU3BYmy
	sQAqQaw7TNlGTvGtopHSniwX2kdot3BxNYnUAqpypqaVrkXDFMnmzQIdRlmCoNrEag4dr3rrJC1
	zCSNNnTpAK+dbO9ojZwko04z6nCuVvYRjLaY6z8aT3qyn/P9QJIzABTNOuaz6yZPsjeOXwJZgUe
	d7fJPr5tx9U3v617fQ0pwRKrEv+lEiJLloSWkDxyOVkaeuc3eotdwVR7ptJj+7Dt6gNeeQfU4Cu
	XMJGmb8GIScdn8oeu79gEbJjpCwNeHmQnaY1kWlaxxocSo+/pMN8tbS1EgC3til1JrWe8DKWIMf
	4InHIvzV82cyT9tYotDy/UYOLuMH5OluA4Yw=
X-Received: by 2002:a05:6a00:982:b0:76b:d869:43fd with SMTP id d2e1a72fcca58-7761216815amr3249434b3a.18.1757671987091;
        Fri, 12 Sep 2025 03:13:07 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7760793b6b1sm4934804b3a.20.2025.09.12.03.13.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:13:06 -0700 (PDT)
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
Subject: [PATCH v4 14/21] mm/ksw: add self-debug helpers
Date: Fri, 12 Sep 2025 18:11:24 +0800
Message-ID: <20250912101145.465708-15-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=M3N4bFkc;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide two debug helpers:

- ksw_watch_show(): print the current watch target address and length.
- ksw_watch_fire(): intentionally trigger the watchpoint immediately
  by writing to the watched address, useful for testing HWBP behavior.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kstackwatch.h |  2 ++
 mm/kstackwatch/watch.c       | 18 ++++++++++++++++++
 2 files changed, 20 insertions(+)

diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 5ea2db76cdfb..9a4900df8ff8 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -47,5 +47,7 @@ int ksw_watch_init(void);
 void ksw_watch_exit(void);
 int ksw_watch_on(ulong watch_addr, u16 watch_len);
 int ksw_watch_off(ulong watch_addr, u16 watch_len);
+void ksw_watch_show(void);
+void ksw_watch_fire(void);
 
 #endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index 795e779792da..2e9294595bf3 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -161,3 +161,21 @@ void ksw_watch_exit(void)
 	unregister_wide_hw_breakpoint(watch_events);
 	watch_events = NULL;
 }
+
+/* self debug function */
+void ksw_watch_show(void)
+{
+	pr_info("watch target bp_addr: 0x%llx len:%llu\n", watch_attr.bp_addr,
+		watch_attr.bp_len);
+}
+EXPORT_SYMBOL_GPL(ksw_watch_show);
+
+/* self debug function */
+void ksw_watch_fire(void)
+{
+	char *ptr = (char *)watch_attr.bp_addr;
+
+	pr_warn("watch triggered immediately\n");
+	*ptr = 0x42; // This should trigger immediately for any bp_len
+}
+EXPORT_SYMBOL_GPL(ksw_watch_fire);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-15-wangjinchao600%40gmail.com.
