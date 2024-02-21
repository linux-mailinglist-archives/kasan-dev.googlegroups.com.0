Return-Path: <kasan-dev+bncBC7OD3FKWUERBUVD3GXAMGQEHZNUBUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D52985E76D
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:08 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-365067c116bsf54810325ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544467; cv=pass;
        d=google.com; s=arc-20160816;
        b=LbJpoLeaIawNK2b3t8DM98LoOuDwuSN57uXjQIKzKPmQlreAbq8UGPNQYPwTMokHzd
         1nt2z2Cl75Bqxz8z2pvqC019fVH97hnYNYpa64dNroALBoLXl9lkliAl33Nx6VyfFddC
         dqexlH1r7Rfi2z4cd/OL5PL1R9P68bOHcgKFN7JmH00WRYrxl3DjkNy6ss9Ha//+dIkM
         6IDumH4ljvVvtz2G7c1TGZhOlg/wLNxJz2GOVLhEzSaeiOAZtq+EhaCvmfUVBz41e71M
         L/xF3FmGFNNYtYs6tLQKkbAWWYNNNn6R2EcuzrXUckg70ZauWQFp78IXXXms5bK7Yl3h
         csKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=mPqrzCU3GAZydAxxdyKTdvntzOGL7zH30k4MoDv1tio=;
        fh=8H2DSV6W3jVchcp1e0BZ9UtKUBRv5C9vjLWokBIq1JY=;
        b=Uj2siqW6frrpK3YK5iE6TES4P0lovGS8Zh/Dk9wUcBax52F6oxtnqePSYCI9LjbfyV
         +faXdQUM+iSgHLApimNPaJaapy/gIMM9QbG01gD0kiCD5W9J7df5euDt1p+rQ1bB6R/s
         Ob9tDxY0tTBBRsLd2L9kfc0k09wmYCVhYPHPv6ehN0YJ/gItHzUc5sZPRgwspMKS7QaG
         oYXJm5BW8BcN1SmzPS2vAfVQBk8BKyBeEGHiJQl0h2v3N/PMzA0YJw6DO+FiC3q9N2Wj
         Y/MlQnaahHcwjSH/B5JJkTdRNyn7GtrqIYn7MBtnzTlNenm0kvG3Gm6n4l6VViy9Lhr1
         hHsg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="gsjx/ffd";
       spf=pass (google.com: domain of 30vhwzqykcqqwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=30VHWZQYKCQQwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544467; x=1709149267; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=mPqrzCU3GAZydAxxdyKTdvntzOGL7zH30k4MoDv1tio=;
        b=PO7hcsLcxCIioEj+gOzVRkOPZ8a/J2g8WOMy/C8RJnieupobKHbhUrlNaRCEw/oLEz
         xB/oY143qR1xYVEOvJU0fxztzeujh16Cd21DsGwdqDsckWWZDDD0gJkIBW9I8P+FJgUF
         4WtZUxH46waXq8b2riaFyn96o0Y+AyRkRPwVXuCS7sHUYFHEI3RhHSssRl0Ee+MF6/rT
         uMRd2dIRoS6TYTOmN33jD8+JCyZ01dPjqzLk8X/3/E5mN2zZx+i6SeTqpwL+nTcWiPUZ
         DNY1QElXp32X3Ioqj0nT6GfFIvxGr5d2WjqxjXv75QIGVP+sKIsSHvBZIXogd7Y0TbQJ
         xXow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544467; x=1709149267;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mPqrzCU3GAZydAxxdyKTdvntzOGL7zH30k4MoDv1tio=;
        b=h2ZpY3Q9NABiJJanjgF2Tlox+M5k8cmXYAc72KCas/DNsZcc3Bdva87V7afdqcdbT0
         q4MvTYg23jNNoZz0ZKssi5B5ML3s5+fppH1fhKDRwotkyRD4Y3SQZVpSb0dked0iEkEg
         XOsaWbCtDnP2xrdeUBuis2MzcdofwZL0qW+Iktzi7M4HeH5x/HeZHPs7yH6o7uCX4Swh
         gIb4O1Yr2Lu9PxBp1LStySskxaGzVSpZ809hQITOokaGXsVWZqS3ZepJZJHZhZ38ur4R
         9A2XvubWbudAIKPr5m3NuGpRmg88vj4MnhU9/I6LBqbGP/sPK5zQZz1wDbB4u7ZswADo
         HIUQ==
X-Forwarded-Encrypted: i=2; AJvYcCXNI5Mu/XZs2Di+h3AW2LkRvb5xb8BGg8+ZN8qIDTPaD1q7Hj8FNaIOI56W8nhzjuNZXh/LzMMCvmRTKaISGGglUaJYSzvgWA==
X-Gm-Message-State: AOJu0YyaBPowS4DBDGUT002SrAWQtph6w9/WPe6eX1Z9pS0uKr7A4WS7
	kSVrY/PoOlWUCiufqDXMoLOcTkeWWklPRKVaf7JxKeV77OWFt3kE
X-Google-Smtp-Source: AGHT+IHQQ9DUfKTQgxoTSP3dNEJPRaSxBmwCjxXf89SfH4qDe/yiBUgbfkJVBHqhQrTyyAi5aidAgw==
X-Received: by 2002:a05:6e02:1c8a:b0:365:2624:30b0 with SMTP id w10-20020a056e021c8a00b00365262430b0mr14209784ill.24.1708544466806;
        Wed, 21 Feb 2024 11:41:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:ca7:b0:364:f464:c52b with SMTP id
 7-20020a056e020ca700b00364f464c52bls1969699ilg.0.-pod-prod-01-us; Wed, 21 Feb
 2024 11:41:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWH2JvMbsHqviiTaKxx4BTwlfiGyYWVEShbJnyxaH3dHjfuRyHsznYqV0BIo6tQKD5uACHw2Vsc3Ank/8RNB21ke1+rF0qjX6ot+g==
X-Received: by 2002:a6b:7948:0:b0:7c4:9c39:3ef6 with SMTP id j8-20020a6b7948000000b007c49c393ef6mr21913612iop.17.1708544465932;
        Wed, 21 Feb 2024 11:41:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544465; cv=none;
        d=google.com; s=arc-20160816;
        b=oKZ79kdK/D7E7xT7mDCT03fHfSH0yT09qj0KeN1uw35zv0qb9vIz/MYiQtoVM/Hg+D
         QUXj5piPxb6oyNhiLOINiDdoqUJ1F0lq4aZOrjXLFHfT9mFgvtvw3cVsCp96dbtupO4e
         j+X/KNShhPYzjpDcpQDZ4fRJW+wogsvRzmizUmA2OMGJGabSE6DANFKloZpAAeIvab1X
         lpKD4YTjvbqi8vU9PGzDHpYo0fPGXtbt2PjH9fGV/TA0kXq6QC22iCO7SIe/OFFgWzJf
         /H0TAo+n+62ntduOMJVv9E112YEeVRvVWVO6v2+xfRH30Qm3d2hbk8HMTuLoHz7WeYNV
         gXkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=nNOJH11gO16gI1CGV9wD1JhhI3G0pl89I4/43bWDXAE=;
        fh=q3x95BYfDkS/NMqe8Na1Gi+3fxmji13zMavder+xn9Y=;
        b=xr6brXZ66eNqTDZsNJ0S6J6KpGh9Dn90jInuo7lGPwJZ/a1uGDmDU/cIczYBru29xt
         zn0O/kBDI+4JEhxL23Kd4vhSHJ8ZnnRzqD9VcQ6mmu61UGvZLSiQ3iJ34wo2UbaoJXP9
         rE5oj0R6JbGT7SrjsLxenNQWTVuDWle3Q5lZu1O5JeiKu+airUL0GnhNuBWMJasDef07
         exhmwtcNuKyoNhpPsz2m9zqabkcKGVNRbhphMFqnP9vg9AKIjoKbzdtNeNKO4MS0WQnq
         HeQZRZOEyLMqk8II6/zdDqgmz7i+02KsdPGq/bHWQFMdqo2avaFnTLmuChEXuYcgoFpm
         fQHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="gsjx/ffd";
       spf=pass (google.com: domain of 30vhwzqykcqqwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=30VHWZQYKCQQwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id d126-20020a6bcd84000000b007c727d87a6esi1099582iog.3.2024.02.21.11.41.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 30vhwzqykcqqwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-607c9677a91so17918757b3.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:05 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWWvMZUBTXJ3toY2kTrNx4QhYxGZJigZRRIppTJN+UmaXzgeh+sqyLmjgQBd8/H++/KPdvMTrxcRgGuEWEkUxzBgtBaNBBRP3cjrA==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a81:528e:0:b0:608:94cb:6f6 with SMTP id
 g136-20020a81528e000000b0060894cb06f6mr174090ywb.7.1708544465320; Wed, 21 Feb
 2024 11:41:05 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:17 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-5-surenb@google.com>
Subject: [PATCH v4 04/36] scripts/kallysms: Always include __start and __stop symbols
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="gsjx/ffd";       spf=pass
 (google.com: domain of 30vhwzqykcqqwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=30VHWZQYKCQQwyvirfksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

These symbols are used to denote section boundaries: by always including
them we can unify loading sections from modules with loading built-in
sections, which leads to some significant cleanup.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Kees Cook <keescook@chromium.org>
---
 scripts/kallsyms.c | 13 +++++++++++++
 1 file changed, 13 insertions(+)

diff --git a/scripts/kallsyms.c b/scripts/kallsyms.c
index 653b92f6d4c8..47978efe4797 100644
--- a/scripts/kallsyms.c
+++ b/scripts/kallsyms.c
@@ -204,6 +204,11 @@ static int symbol_in_range(const struct sym_entry *s,
 	return 0;
 }
 
+static bool string_starts_with(const char *s, const char *prefix)
+{
+	return strncmp(s, prefix, strlen(prefix)) == 0;
+}
+
 static int symbol_valid(const struct sym_entry *s)
 {
 	const char *name = sym_name(s);
@@ -211,6 +216,14 @@ static int symbol_valid(const struct sym_entry *s)
 	/* if --all-symbols is not specified, then symbols outside the text
 	 * and inittext sections are discarded */
 	if (!all_symbols) {
+		/*
+		 * Symbols starting with __start and __stop are used to denote
+		 * section boundaries, and should always be included:
+		 */
+		if (string_starts_with(name, "__start_") ||
+		    string_starts_with(name, "__stop_"))
+			return 1;
+
 		if (symbol_in_range(s, text_ranges,
 				    ARRAY_SIZE(text_ranges)) == 0)
 			return 0;
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-5-surenb%40google.com.
