Return-Path: <kasan-dev+bncBC7OD3FKWUERB5XJUKXQMGQEWEWWC2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 9744E873E71
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:24:56 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-6dbdc7135bfsf70583a34.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:24:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749495; cv=pass;
        d=google.com; s=arc-20160816;
        b=cRjLAoyPSa7Ch5xCUQ2QREQL8GkU6a0yW2Sf84pD4qt5w0aN8MVnuU2A4UebKWK+uR
         l1e2mTlglvI9yA8V3lwGXgbCtm7lPjQzy6mOAoB1SXawgpzVLKPMxRmK7iL+fmJwFsbl
         BC87Sbvj/t0l7t16nNNG9A6tuxtmN912Do0TCCGGSUora9Tb7siZ3z7faABhw+L1k7Mi
         +htQ1p2JxKEMb2vPCNK9OIwrq2uvfmUksz6kqpbt6qFJZBpLaRQZGUu//o1g2FpqOvcv
         ZdhahWPK7JNdv/yQcNJEk6MavNO49NBY/GWHBIZsRh8W6mdn7ftbPljDstl3NUwWZYfh
         t3HQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=LtLZFRyU/Uy0DNrg/EKuJEjQRBeJ7q/SD2ei9cl9yMw=;
        fh=wL48t1ndTCu01Kh1QxnfM4e1bnGSHEyFq0a1kJ+ZK3M=;
        b=QgjELf4YBB3GSwjdwiaHdJd4w3BmfdMxBgCoPkfIwdwexMkhECyabLGOoq9saMnyao
         Upksh+9bvygrov3FBcFT9ErAoLqTa5r4gC4t1DIjM4h9gD3QPJF06tWiHf4Dl8Sc1qof
         IamvyvzuReeb2UgXxMD63zsejkpDsvvHllj+SmhXExYgO6QbKfv3j2dKxAfcojZYL4Dm
         Ck+GRt3W/C5WHw2y8INlKQe2YVDRxP/kZHP60fcoQpptAdmuFoQxWoMv9Tj7I+TqtHQD
         zBcG7ATYbJoZdzOKkTU58nBLmoHFDEHTQZ+CYXnALWhMWWQogCxUo0sjIYHt5sDPG672
         OIBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UsUVotWg;
       spf=pass (google.com: domain of 39btozqykctgmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=39bToZQYKCTgmolYhVaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749495; x=1710354295; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=LtLZFRyU/Uy0DNrg/EKuJEjQRBeJ7q/SD2ei9cl9yMw=;
        b=p9tBDJBrpOJvcLGOjM+onNzcGclBYu4pYfB4njA8AbmYdehdyhxv668sDR1mHuB7P7
         8oyBQ0oztUURileuN7PbVPOAwIHC20CQej05GjKcrzjmWIGJagkW+V7ad6U9SZILwH+m
         BxKmmHesuJTi2DoM6e+wxEsL3UXhBv2QP8xQM8yz8QjVuHKASLc4rC4Zb1wkFLUGA/AJ
         7qktniD+rPzyC1SQ7kNZai1nEODq444z1yUkrIZynKgPVFzGWcOk0HvIIcF49vZ3vptz
         lC51C9OKSjKPjzc+aCShxKswXm4WpNmXxvCoj2tJP1rYy4xKSctSaymFaxq/UG+dXA9H
         XgVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749495; x=1710354295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LtLZFRyU/Uy0DNrg/EKuJEjQRBeJ7q/SD2ei9cl9yMw=;
        b=QUPEhptKGqgc+xb3X66Z9/yO1rPBHW4IrkhwbXbsLBgzWMUdCTwixv6vcCMRvJaQOo
         tRWt5iJ/uHbOqWlt//UIqMQhP1yZziqoLyPwXWRphXeVNAZhXtcm8IFsEfNQcaOwGTv0
         IpRoo6CfAmrfBc3wwZsmCep+7+5t1x5msQA3QR3sSKH5hSzUYev2cvyGaepsEvX2IGac
         QC7q9yjArjQKwld8uhftfRv0JLGDf3b+unhQb3frAbI00dudO9/6IGbMmn3U2OJL2YAn
         DN4WMBYrAu7Or/t45+CP10BhoOm+mAZLPWq54I5AnMVPLLoEdhmP33GOrKh5R9L40Cxy
         KODQ==
X-Forwarded-Encrypted: i=2; AJvYcCVnEwyIXlgVCZ04Xx7y55HrISb0uiWQtdA5cAkxXiQOmGOQ0LEOOaidQNUt44v23XQcigpRLA0+Y/5eZj/3TdwObYfk2fHV3w==
X-Gm-Message-State: AOJu0Yzrx86XHfGDJQuyyksckC4/J6PlxMYv6TMqG9YGrOiLrlRV0GKq
	sB2/B6KfvfONp4lsFc2sr6MSj9fZzeOzY0CLtuv6jZaTeI+jLI0P
X-Google-Smtp-Source: AGHT+IH9243znc0txMj0YiyUCpEgg4ptkfHvMPbz4vNHFylOs7xg6zcIc1+41uwXCNYb+ZFr1Tay9g==
X-Received: by 2002:a05:6870:20c:b0:21e:b8f7:9a1b with SMTP id j12-20020a056870020c00b0021eb8f79a1bmr6510788oad.25.1709749494992;
        Wed, 06 Mar 2024 10:24:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9e8f:b0:220:4300:c4ef with SMTP id
 pu15-20020a0568709e8f00b002204300c4efls57417oab.2.-pod-prod-06-us; Wed, 06
 Mar 2024 10:24:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWdHxCvU5UcE+kVhclLbPs4BRVxb9FCCiOZIcFgsPENg5M7/redokUBdnedhM9NgB2GSrLTZAm5yPm6T0l4gmpyKBm8xq30YgwtBg==
X-Received: by 2002:a05:6870:2490:b0:221:5c49:5d02 with SMTP id s16-20020a056870249000b002215c495d02mr1919859oaq.51.1709749494203;
        Wed, 06 Mar 2024 10:24:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749494; cv=none;
        d=google.com; s=arc-20160816;
        b=UCDrCApKqgrsSV/JZgUbiyhpEgNUHY31ybadOP5r/qf0LKzZK2APfLvPKo5ySQxTVJ
         Z3kUEmBE/UPwXoN7+dykPW1RqbrR9g6xak5Oh6mmX3VQFnqj7vQ4fB9gnkv/VPgVXOn1
         opC9sMzsJ5dfc8Vi1WIPl+qiIi6V9GlnN53lMUZxelRLMU0JNDkZXJyB7o6Q3elOfrZq
         PAhsKgpgnT1Pr3l8m4yJXDcFzwTfcZmqxPw0jdy/fa/NUo7Uv0gcim5atNV8di7DFPKS
         sETJeUVxCbUyPG/s9j9iJZvawmI4k3UXmJgXTg8qJ943ELudp+J9LUKM29/o+xF+986N
         t4og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=5nTBv3DNXNZIxIc1ZBoC1bDpLfB6IB4LOR7eT5PZErs=;
        fh=0Evi0WHJI6vmifPyR/uw/DWGjfDTW1CDxTL+HmGK2gU=;
        b=aZDcOlcD4CRz2IGAO/bG4oI5Rq6yDtmhFPyEBPbBgCs7yRirmPHfmYYkID3naek4q0
         n+fZaM/qGKk5b1pWh65jzIgb6RcBPczvxLj1ZFkLL1tIW7LGSwGqq4guEsBsrjPKSsZN
         KuiaqA42oXIL3Kz21kYN9oeTeLB79pcAEG0Sn74vg0twYLClBRGwPQB3tWT6c7/rLIfz
         5LeoReywp9PbjVPuhkQD+Gx0UDZFBvt3PElJGdq0DYYbA+YSXHDauyiqEcGdP7IILqEW
         HlrdIydc9JuhlD7GFLs7MQ4rdkBfgFlnzrPTycd6/3LSB0+kPL2bi6YIVHRZDvYuw1dA
         p1bg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UsUVotWg;
       spf=pass (google.com: domain of 39btozqykctgmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=39bToZQYKCTgmolYhVaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id hi14-20020a056870c98e00b0022094292079si1895804oab.4.2024.03.06.10.24.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:24:54 -0800 (PST)
Received-SPF: pass (google.com: domain of 39btozqykctgmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-609a8fc232bso669907b3.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:24:54 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXinix8SvKeLwt/BgI6EDYZO+UkelEStKSbhv89m7npKMD8xtcLucwAIPI/GPep64Nvo1Vq04ydoVCGERMj87Koc5kHNZrhGH0KUw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:1009:b0:dbe:387d:a8ef with SMTP id
 w9-20020a056902100900b00dbe387da8efmr534074ybt.1.1709749493516; Wed, 06 Mar
 2024 10:24:53 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:02 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-5-surenb@google.com>
Subject: [PATCH v5 04/37] scripts/kallysms: Always include __start and __stop symbols
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
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=UsUVotWg;       spf=pass
 (google.com: domain of 39btozqykctgmolyhvaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=39bToZQYKCTgmolYhVaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--surenb.bounces.google.com;
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
Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
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
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-5-surenb%40google.com.
