Return-Path: <kasan-dev+bncBD53XBUFWQDBBRFKT3DQMGQENYHUCPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id EF225BC8A26
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:58:14 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-32ec69d22b2sf1837222a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:58:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007493; cv=pass;
        d=google.com; s=arc-20240605;
        b=kGEMmCVAYs5Csst6i5Ws/j/zAPzpT0ghopLPD+JYYEu9crDApuP8IU3Ft/9eH3NE3q
         doTGe4MfjrvDMNTZLAXb3Y3K1jXnm+F/sZPN+QbPr7F8HBdTtUyxQOTFVguA9seyQu8e
         QZaMum1U4YZnaPwcjaw7NmYNqJ8eAt2sRT0ulEbhl7tc2hIzHWl71xRcP95hmi4gfYLB
         MKGcr59Y20kLznvL8MOgeaWgknBbnjy8Im/dplr0BTsZnyrmZyrOxmQrcvo7bWE4LSnJ
         bKy7QOGfmrlsQ0KvIf8RjLnJQzic+7yT6r+Pw5YN/pkjPtzX6V1tvWJdkyijTWKClGib
         DO6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=nmHpkH2L+TEq08uWNVbdPsq8VM6rFyWRbUXZicPVi2g=;
        fh=WrNoaMCSMIPaNFogfgOdUBZpkpfccGa5J0eHN+72uGg=;
        b=G6yVsqqgd8+68Pjr44vgkoDi3xr7K94uG5Irlv/IO60LiuDNsMPgkWw1PnFFiEJDhK
         bJ93Ys9SAG8/q2DX0HC050XScSLHP4fqjMrLjqZkrzxXxfyCGKP9IUKCHqLZY84twKEh
         D9GgGFcz2KaVgxt7sROuRHKJBRQKJ9KHaQ8+anMvGddW9GuY/lOHDUidVNkd1XNt+AKT
         crfl+sQVPELcN5rnsDHRvU+0JNkWLXgiYZQ4YyMMAdJnIz5n82Rjxszai4H2FA9qmyVN
         ZYN2byGAAhCxZwv2urPok8uGHbWpL1b+aD7zt6KG3dYHBVUAjVPGGY6iNJCessCfRLX1
         cOVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hjGqDOpA;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007493; x=1760612293; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nmHpkH2L+TEq08uWNVbdPsq8VM6rFyWRbUXZicPVi2g=;
        b=iUuHzQePXxwI0Lj8G2k9JUAid2YL+5+g2IpO8xM6YiaAbj6KgjKR+05GEh+vLlfyVB
         QBfUk4LpDuzhrNik0mmOEpq3TPkZNY8QwY8Bn3JiG8/WNPMixBvAi2UAIwbRE+1Fp1Tr
         FB9FGS/P5gCnhzkFndplUW9yUC0tVLnnxwfmL2J9vydbyhhs4iz55MjEpuXQ1vrH1Frs
         ldeidUQRe5G95d7TFvraWvByFYu5VrSHw5xTLOiaCzmoLv4K/PYD6yaGe/pyQdfN23P2
         XR6bWBYjV9aqqthFI9AGWjnqwoNHDPdWrWRRDFltIAGs31+eYyJJyjak+ApL3Ag+mcRR
         7A3Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007493; x=1760612293; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=nmHpkH2L+TEq08uWNVbdPsq8VM6rFyWRbUXZicPVi2g=;
        b=DjxeGsDSHZzsVxdhBEq7PbA2pOB4TPi3zPFYMR8zpCTczQ9jBYJ6BJ/8aMjhEFc/NJ
         Grvtob5jx2NAVpI/MUA6RSBSTZSfEoUU/cnVunR5s6Q6y0Y3CdZVFdFNa1LroDc+pmzb
         ydeyXaoCAgeC8gA63NZZ60eN/8E5lYGg4SwOdKxviFHrxzNiMM4n4NWA8wZMDvjY/sON
         sUAAjjea5jjRSKaARCUKVIiwDSZ1XMnyAVMgZhkH846rargnTtY51C2Z4F6bBGcqTRqC
         zSPQV+eMC8BVzqbJqK7xzMRYZ2ZnWcSYeCjth4RDqS4juQgF3a0uPvoH/bqEdwq7nVH4
         m+2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007493; x=1760612293;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nmHpkH2L+TEq08uWNVbdPsq8VM6rFyWRbUXZicPVi2g=;
        b=StdOJvaOpAqt12MoCQlOPrV3BAKASMarQy4xr8t50fsOuautWhGu1N72r42q4RoR11
         tkn3rgcvumzejXWPGPyPkb848HqzRQJsankO2miMC65/f4XRedjxnDeZBOBmcSeZcvxh
         Fe7cD353jzDjrDFf8dqY6howhpthPucuwDeXSa5HtLV2/ToImURjf4cefrtf9yXFdLiP
         bOvdIwmgsREG6xKZ6kOa3xyZ819EdGvF/YYlLWPRwSm3qUiVUuH2WPvvwfJi2ZyT9uKD
         QLJguRfeiWdU4HQDvSNSKGMnNbpu+Xhv0OXHq9je6LtV4o9kxb6qMO+tsIi/hJXDWKXA
         RcIA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWYALp+HqEu2Q9p9cwtiG7G/aWVTzWARJwvJCIu7FwucUbvXQpnxE8DfrRMKfxvzqO2i19ErQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz3UT/+hxtv4aZ2vKyp/yhJX+SNEdATGDSUXP/ib7eXLXz7S6fW
	/xqGMwpemnzg83JhC7keGmpM5tron18E2C0VYbfmI4MOWxLgi6Yp33r8
X-Google-Smtp-Source: AGHT+IHFXsBY7j0wuLeR0eNAHyjWX6q5dk5/X1zPgFlEvsALkWqvEueYWrb4dCJiTEKPIkhevkpvNw==
X-Received: by 2002:a17:90b:3e8d:b0:32c:38b0:593e with SMTP id 98e67ed59e1d1-33b5114d3d4mr8512116a91.5.1760007493240;
        Thu, 09 Oct 2025 03:58:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7LLHIX+m+HNGqHTHvEz7sh9PUJTa9IizNmJEGWAPLSMA=="
Received: by 2002:a17:90a:ec85:b0:339:a81e:c4d5 with SMTP id
 98e67ed59e1d1-33b598eba6fls893148a91.1.-pod-prod-09-us; Thu, 09 Oct 2025
 03:58:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXTNqoFS9aYvaICGEU8VFLWMUO2zLxUO75xxRolZgH0yztLPhbyd/EnMnSL7zvVxyL145fdOLCtaxQ=@googlegroups.com
X-Received: by 2002:a17:90b:3a92:b0:32b:dbf1:31b7 with SMTP id 98e67ed59e1d1-33b5114d4d5mr8557947a91.2.1760007491811;
        Thu, 09 Oct 2025 03:58:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007491; cv=none;
        d=google.com; s=arc-20240605;
        b=Yp6cAVPazCVy6wtu53aY7Gu18CUHV4XpDRAUdWgGwtj9JSPvOm6Jz+9iR5D4gYwD/F
         jYoiba2oQvhheOpHRLBbo6DZTMIkDqLh8IiU0blmyKBekC4IoY7JzsBGQSiz5/lH8Lxx
         22C7VJ5A6vc7FT+QSmIBvVaILobOPdDZtYFEii7QvkxcMUPAzK8Jg4O6w8+EO393cyj0
         m3g5g1tJ6HgFsCgfDLb1dtr38GWE61JDQ4nz3P+im9IdDwPrDqajJK5CQ8bGMLMonI8T
         XDbWC476f2WUmaM1WBQ5v9oOBJhrbjEBk+PPT7G1OX2nKwfGP97OEbG4ZKYC4/YSCv+K
         ZQKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UmaGbmiuxIsK0xKTEWJ/f7gfwC2bw8p0SOLh4b9Z4FY=;
        fh=HUzeYuFuZjULN4juxqzQBa0TjNU4LSeuegVro4D+L2I=;
        b=lO+wZ/7VKplPj3GLZQf53dybmkJ5fRO517+fhdJe8DX6zXSfl9yvDviG8CF2yjWGwK
         RDDCz4KeXPs/u1JGhXvYge51L1DcV0oLZyRDzuAzH/QWe88bAN7V9+ck4YgwNFF5NH1w
         CA473YnvJdAQ9kf65R1pfEMqClW8/zFgkg0ex8WI91N/rI/b7nWnvd6dkQjXXe2x9BId
         Ka0XKdH/JnJPgjo3ULLZC7BGvY9uWrcfIHDLf9iV1m7b1vrhvwcFrbCRrMX5PW+wQwaL
         ODADCHgL0yUsudX/8lukr6bpVHofqNh4ChNblvNHG8bgCozMZF5mt+VhKGSn4sI9ohHS
         RJ7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hjGqDOpA;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-33b52881235si205533a91.0.2025.10.09.03.58.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:58:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-77f343231fcso667480b3a.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:58:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV+PMZrLWCW/dIMJ+rfMUJ+tszJrJeSq/RD9YMFcrU8C2hOelMxpXltdB6SM/U6JAJSEt+cBtGj2Ww=@googlegroups.com
X-Gm-Gg: ASbGncvrQxCS3nasRGnYN5KsHYULLfuKmyGUYP7Eih2lVw6DIbYLNb/Fw9wQUoIHfDn
	YQ89rI6vOKbQFFv3OmIp02m0yv4WXvRIhJEhAD2SP9alYB/j9PWPc6yBsn99UxVtG/gZv7KzbdA
	0IocbWcAOO0fNrSfABDHj5ycYsTqk9ynrzNkGVOwbpOmsmOaGNx+phBkaAlsUDMlRzC8RkKWR8A
	J2G8N5T0Mh9+enrrefTfZD7Miv2jqTDan+JMXzFz+hi47/v3SD3JWBWHacNviu5w/8FJtbL+XTX
	n8XmBGQ4qQYxBQ++4aDeG/p/nawB9XJF1URNxUC7GYSRycX8aZd8KCRam2sGuTyyJvMdSCWWKOy
	UfLafhmNsx0h4SYFzcH7UhFudnp9hweyZrTMLEgOVFcmQqkeb1afAECmduAtf
X-Received: by 2002:a17:903:2f45:b0:27e:f1d1:74e0 with SMTP id d9443c01a7336-290272b2bd5mr92577745ad.17.1760007491218;
        Thu, 09 Oct 2025 03:58:11 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b6099f7ab4fsm20659266a12.44.2025.10.09.03.58.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:58:10 -0700 (PDT)
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
Subject: [PATCH v7 16/23] mm/ksw: add self-debug helpers
Date: Thu,  9 Oct 2025 18:55:52 +0800
Message-ID: <20251009105650.168917-17-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hjGqDOpA;       spf=pass
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

Provide two debug helpers:

- ksw_watch_show(): print the current watch target address and length.
- ksw_watch_fire(): intentionally trigger the watchpoint immediately
  by writing to the watched address, useful for testing HWBP behavior.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kstackwatch.h |  2 ++
 mm/kstackwatch/watch.c       | 34 ++++++++++++++++++++++++++++++++++
 2 files changed, 36 insertions(+)

diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 4045890e5652..528001534047 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -52,5 +52,7 @@ void ksw_watch_exit(void);
 int ksw_watch_get(struct ksw_watchpoint **out_wp);
 int ksw_watch_on(struct ksw_watchpoint *wp, ulong watch_addr, u16 watch_len);
 int ksw_watch_off(struct ksw_watchpoint *wp);
+void ksw_watch_show(void);
+void ksw_watch_fire(void);
 
 #endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index f32b1e46168c..9837d6873d92 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -269,3 +269,37 @@ void ksw_watch_exit(void)
 {
 	ksw_watch_free();
 }
+
+/* self debug function */
+void ksw_watch_show(void)
+{
+	struct ksw_watchpoint *wp = current->ksw_ctx.wp;
+
+	if (!wp) {
+		pr_info("nothing to show\n");
+		return;
+	}
+
+	pr_info("watch target bp_addr: 0x%llx len:%llu\n", wp->attr.bp_addr,
+		wp->attr.bp_len);
+}
+EXPORT_SYMBOL_GPL(ksw_watch_show);
+
+/* self debug function */
+void ksw_watch_fire(void)
+{
+	struct ksw_watchpoint *wp;
+	char *ptr;
+
+	wp = current->ksw_ctx.wp;
+
+	if (!wp) {
+		pr_info("nothing to fire\n");
+		return;
+	}
+
+	ptr = (char *)wp->attr.bp_addr;
+	pr_warn("watch triggered immediately\n");
+	*ptr = 0x42; // This should trigger immediately for any bp_len
+}
+EXPORT_SYMBOL_GPL(ksw_watch_fire);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-17-wangjinchao600%40gmail.com.
