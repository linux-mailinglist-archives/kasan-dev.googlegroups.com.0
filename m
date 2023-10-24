Return-Path: <kasan-dev+bncBC7OD3FKWUERBR4V36UQMGQEJF4XXVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id AB5457D521B
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:46:48 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-41cd5077ffesf1509091cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:46:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698155207; cv=pass;
        d=google.com; s=arc-20160816;
        b=C+M72nMQh6Ion7M92m88hEa6KlJ87DdLr2yA0Dv/yobqwT6+vigAsA65X6Q95oiY4z
         hiZlN6ivjSAOaxcZ82a0xpP5Uwek9QQSz8N97kKzsgZl75IM4wI/v57Na7aaYxFZpeiG
         w5DINwdxrlw7uqPKK9OKed446m7h57/75ZJBGA+BIuYsMBSrGbUXF3ojsSnlZ2VA29Cs
         lTl4pUsoI2izgTJORTLo5hPKBMLCFfidxfugqo7cGoo15rSC7bajBvlTFFpIBqlY9uks
         rdmJd0dfgog9ZxFcBXk0FH3mlYl+eV1YHfpRL5e4EQrFgtInD0l8yYLXIHt6jfyjVfRs
         2brw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=/EMJPOYES4vGpU5Fw/Ma6ObHSAnu3do1ypF2GBYuQYQ=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=Rn4TjLL84aZbj3SoDysAdTB6If2nNw0mxomCWiOBIhy8K2LPikkdoWEV0Moxt4Qn5f
         8K3UkqFivP6toq4CjIlhKcH8wnI2dHMhyYcszxs1euKXJbUe3aRh8l7GDNNrHp6j6Js2
         JbGVINImpZMBULQZdxR2i70DndztadYRyWeWFR+t/m61G1UyUsaAIxDCPBTkWln78jvU
         tEOYsG8LcmHXCp/F6OcwlcysVBO7osLoqBC0/QPg2AVZtWHuET5WfRb+mpyAQ8eidN4K
         NX38yn1sBJ+cweVqrbMIt3WuMTWANDoWJTTmKJaVndyUCPi22DEr/80XMD5iYg2PXn8D
         WseA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Y3uZOEGq;
       spf=pass (google.com: domain of 3xco3zqykcwoaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3xco3ZQYKCWoacZMVJOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698155207; x=1698760007; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=/EMJPOYES4vGpU5Fw/Ma6ObHSAnu3do1ypF2GBYuQYQ=;
        b=bbGSbuCnpbNZVnn9WhMxaZSnFgXRX3eauiCTFShddPXpqzyI52BR17ANPdPK2hsLmJ
         ZDkIipqvIQ/sDD1pKBNR30IskKurCcj8uLnk+Ji5r/lPigtlZm0wNCdBttQ0YzGt+1O+
         IFRvBV/KUdy0tdciMXKi2F9Uq7QRev+5BxM+WLLig+VEu4oKU1SxXm6jVJgO0sx5VYhX
         q2h1QvnnDgcz8yhCUzDoJv74HyXpP481yW5JWTTUdam0KkWf4f9BwuJX4n6+guAMwWsI
         UkBDDSpMFuWdIWIw6mZyjnDF+pzgwqlYpoIJSRWVejw7/gCUy9D03lkNKBowOJiCGiCq
         lowg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698155207; x=1698760007;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/EMJPOYES4vGpU5Fw/Ma6ObHSAnu3do1ypF2GBYuQYQ=;
        b=aHXVRpIoKxV/DaApuqjQTOXn4KgxlEuLddnGsnOc755oGW8RysZllJjsG9zsKcC5wt
         cb5sdnJ8BniV+hJ18TjVGjtNqenv2XxcfaAmUFImOvs4uaVD+kzesONlLXWQGldQajpG
         UZl45SBzJZ0bYqudGHdaZIwn0fogOSBXgb6espQNSiCJgIKVkAiQ3QErzEeTU46LSe1C
         E0ECgjo/td7giDeurjZXRdPPOV88rRRhaBai9lAyfWAK5oXnbGecfhsuNEwD11heLpr5
         pXP6YGKeXZ1Zo7s8dfFtEY3ppcv+eCw1bDRBipDaBywqnv+Zje1QGGIoSbOmGa01y8rP
         ZMLA==
X-Gm-Message-State: AOJu0Yxur43hfo3ppGkN5SHzWU4DWDnW4UTjidtUMz0Ht3gLhFVOSFMW
	pL3JZXxi1sYXaDCCfLwlCWk=
X-Google-Smtp-Source: AGHT+IEFPyAVNs0nR3BePspT6sX0qeP/p4gIIJiuvu12UDKfGvDO5MvCN4/lXZkbAiKI4WmicDaW0A==
X-Received: by 2002:a05:622a:2c4a:b0:3f0:af20:1a37 with SMTP id kl10-20020a05622a2c4a00b003f0af201a37mr233860qtb.15.1698155207509;
        Tue, 24 Oct 2023 06:46:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ef10:0:b0:65d:b9b:f310 with SMTP id t16-20020a0cef10000000b0065d0b9bf310ls349171qvr.1.-pod-prod-00-us;
 Tue, 24 Oct 2023 06:46:47 -0700 (PDT)
X-Received: by 2002:a67:e1d0:0:b0:452:69f8:a00d with SMTP id p16-20020a67e1d0000000b0045269f8a00dmr6401459vsl.2.1698155206756;
        Tue, 24 Oct 2023 06:46:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698155206; cv=none;
        d=google.com; s=arc-20160816;
        b=HEJOkZnEQuQHzebqOfrAs0+bNwtAuFlruiAMjclnxjBOf3kwCv4ArtW42LN5vsAJSp
         vU1kFVNoPws1VrY1uZ97E43l5ELtnLzB6GAghQsppsPVZUZnf3dIXvr00MozhBxgREkA
         zFCQzmlQOqAam3RNK3zxjgWD/q8I+HB4MKza29R+NeV4gFLDCfK4+upEju+LCqe/dmXD
         TjqzyC7BG33oKUOyPMA8THWaVnYuxTmVvnAHZ9j3V+GqmMbYCGqiCbojPdit+Ermxmd9
         l7kWmkjNe17khE++qaAk3r+bpnWfkP423H3ZV4RpMePJ6eT8zzKOaRlTb+pGF2xO3ss8
         wFMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=fObhDXE+DfK48fbfXMStFHtHAmn90M4M91A2l4CxzLM=;
        fh=99ic5ujgrZ1PmcUIp20sJVy5ooX2fz6OKB+cA08Xtj0=;
        b=iQRTSXM881bDlSByuyQO35wYO7SF/YiBc6RTSHbcVQBcZidPYUDUnc36I/RZvs+45V
         lZ8ZO+asOsIj2IgLkQqj8HBC+XgkwK6vl1Bz32DbxSTGWCTCf6pVZd54N/Fc+6iV+52o
         QCzrMSCmx1llcTySomTWqsxW7HEAYb3oGSADUYfD9GXDy+Adk497ZCB7Yo84FFrqZFnA
         AO3S9U1q41G3tSSh6eXbkGCglbW7wFM46+TAyqXXK2Ob90RQhqGUN7caAxubMW0MFId4
         SGj5lrZF5XGm2hEzUIBMOZLYbR/h1ISzEsbq0vqjDK0oyN75S+l2Kp/Bv1HLk0ye1730
         igXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Y3uZOEGq;
       spf=pass (google.com: domain of 3xco3zqykcwoaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3xco3ZQYKCWoacZMVJOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id h3-20020a0561023d8300b004508d6fcf6csi960021vsv.1.2023.10.24.06.46.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:46:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xco3zqykcwoaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-da03ef6fc30so673711276.0
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:46:46 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:45ba:3318:d7a5:336a])
 (user=surenb job=sendgmr) by 2002:a25:5008:0:b0:da0:2b01:7215 with SMTP id
 e8-20020a255008000000b00da02b017215mr55818ybb.10.1698155205957; Tue, 24 Oct
 2023 06:46:45 -0700 (PDT)
Date: Tue, 24 Oct 2023 06:45:59 -0700
In-Reply-To: <20231024134637.3120277-1-surenb@google.com>
Mime-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com>
X-Mailer: git-send-email 2.42.0.758.gaed0368e0e-goog
Message-ID: <20231024134637.3120277-3-surenb@google.com>
Subject: [PATCH v2 02/39] scripts/kallysms: Always include __start and __stop symbols
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
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
 header.i=@google.com header.s=20230601 header.b=Y3uZOEGq;       spf=pass
 (google.com: domain of 3xco3zqykcwoaczmvjowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3xco3ZQYKCWoacZMVJOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--surenb.bounces.google.com;
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
2.42.0.758.gaed0368e0e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231024134637.3120277-3-surenb%40google.com.
