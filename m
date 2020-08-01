Return-Path: <kasan-dev+bncBC6OLHHDVUOBBVNKST4QKGQEKGLVWCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BC2A2350EF
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Aug 2020 09:10:14 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id z16sf23280355ill.7
        for <lists+kasan-dev@lfdr.de>; Sat, 01 Aug 2020 00:10:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596265813; cv=pass;
        d=google.com; s=arc-20160816;
        b=BWR3f7PIPlPPVPcX5usi3OATMZrxHyrj7Igfy4W+cIHaVmaR+VDw2SGrnkjD6N2Gt7
         Va0cJ2xVPDBI2KMmIlg4/0CrN1QL4logeCDLW1NDsSx7lkp8c25JdnkjnbvYyQHUHwOI
         N+aOH8yadcHInSe6YK3cy+HGTb7YwzkzHmVSNdCMqO6yTvC8+IoHWNmKHmMsdrwnauew
         k4yJQ8rTpz+XhxNMsfdyW5lZj0DbsAoXAKkfjPXxPR1YG4OsRS3U2sZi4Z5puWQzxWZv
         utNVbSKdEUIViCEU47cdGVdleu2TtGD4nbFw8FKJHHrYbzUQUYUlqfa4wWdD8p0/9wV2
         AYAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=qun+953+MlTu2pDYS4HGrOEo11V0uFOV4PG8K5ZiUhU=;
        b=ORuZWd4krW7HtUP95gy4I+t+NfYBsclycNJ3ke21+WsFISgay+VgC0eNCVgWQfA07o
         KooiXuO3cbSUE5RViJ2plBbGoHADwffj2Z3Vv3eNBhZJk7EUZx3CY+CGMtswEKVTqjlV
         vDkTZNZPgn19DCjdqAmhobx3YF/mR6LgwFaber5DTTchIHWsYgM+M6T4x6+jZzexz9qm
         jSp1h8gMGLLM/Iw0eTaX+ksVnK+t1CnPoSWdOngIcAwbP/7BzlfeRfR0QsoPPeloNkp9
         mW4O7EyZgtkD10IbnwaFJmWXJlNLoK1RmssoU2D+S1uw/qVZlu/kMx+Iw39V4zbXRXQN
         z4dA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p06i0vZE;
       spf=pass (google.com: domain of 3vbulxwgkcrmwte1wz7fz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3VBUlXwgKCRMwtE1wz7Fz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qun+953+MlTu2pDYS4HGrOEo11V0uFOV4PG8K5ZiUhU=;
        b=Qn/Xhd7fnAOP8KXBfJCQIX3Wf2ZLlVc4cF2gbEOMpo/tVouKQhgdjum2PPmpbnxp90
         k4BBiYVoBphsLMudHxjnJPb+j4vyD8Gg3Kh841Lp/oV42XDeGcDxOx/27K9duJUbCzZH
         fFT213kZprBhtP6OEnEZTG44gAkkym7FEq9PBzKW2hnnnNXpqcXb5WaTsoEVlyFtd8bS
         sscwN29RyH8ypHEMFfnCBmVDQzimIpG++Ntq1pp8K7VC/esApLsMDeAEkEC6gRyXghDE
         egjbmebfa1VgOuY6QwizSFqDuNZFeBuAJSZMS0rQBQeoIZCHpj6nddydenXDSGIo5O4Q
         ACsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qun+953+MlTu2pDYS4HGrOEo11V0uFOV4PG8K5ZiUhU=;
        b=bSAC13wk6sbECRfuiy4LLiqrHgl2UljzGjvhapaK5USNbJ5N1JThhhQNQflw8qMfPF
         svPEfRdyCsqIhO5lzkgG6EWPP9frpG0Azvp90JNppIk5Fu0PwqM0vqECgPeignJEC5WJ
         JRilvDH5bHBgLdJGdRav+AY96jOiFsOBCdKHzyaM/zorDvmnfcXJPA2Dhb9iHPy73YJO
         ONqT7eIFpCo3txqHGp5CICyLnlKjA3v8ffYd6SCqwEnmhB9IKpTNuohcVkXych3YUW1P
         Fqecd768RJHPgY0SocLOBruH/p6blBkDEfFghw1Jx/2lUJ9tof47q9Mad9bataysG4+7
         A3+A==
X-Gm-Message-State: AOAM530wFSaQYJfvTdWk/3VB8h1rsyB5RuFd7g3RNA779ru7DLbT7GIf
	UD+bNMSz1voqSQASnnCUVVo=
X-Google-Smtp-Source: ABdhPJzQAzAaCw1f+o855ZARvs9uU51+fkIM5Jp+ROp1ySHxGe7zVFGGr+2lPikh6EOW+v7bCPd06w==
X-Received: by 2002:a92:bbda:: with SMTP id x87mr7673083ilk.242.1596265813459;
        Sat, 01 Aug 2020 00:10:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:974:: with SMTP id q20ls1935106ilt.1.gmail; Sat, 01
 Aug 2020 00:10:13 -0700 (PDT)
X-Received: by 2002:a92:db10:: with SMTP id b16mr7510071iln.288.1596265813148;
        Sat, 01 Aug 2020 00:10:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596265813; cv=none;
        d=google.com; s=arc-20160816;
        b=PTCUgDD0tqTsdPGMfgHtuut9ISnL5obl1IIpDonX+UGASZx/mRYbg0aOi9nbxVaJ9o
         uvSPQLUjxwvj8MfPLmXAu76Dmzy494R+YHiaOko8/mrVRyYEt+E7Z7LOBqKOVL2WCxRf
         +MaTV9MGoWREIrj2jb0TzJT8utBJwStL8h0b1c+5De4RTqwL6CBCEucMD9RCOWGMed6o
         u8BEvRGV5+zPWx2ecfMUZTdOqiIvuhNeXNapHBuhKXpPBr16ZcOzgXnxEIFAQc2F4foD
         mvvNoiOpMYK0AT5kOzrbu8akSAvueSzl9Rreep1san03ydMcN4iv2jZlC2dYj4Xv9HvG
         9EPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Y00REmw7cW2Ho0KOM1NABcGJpQIr8u0gXHD6A1O7ZXc=;
        b=j/yEUuQ1B+Ycwj8Q9ZYv9DyWLr5CWHuMT1ASdCTHgJZ640SlKo0EhedGL9yZSC1KPM
         ulr7R9OAhw5mnX2zP5Se2tAk87IdlGyzk1Yt4JLuN9ZqYoLTMRCgBwtLyfI9coZuaIAp
         m4Udpj6NV3SvsEUy3xplh0I3jzs2pG606gOuWp7PnS/jVbetnC2bWFlwjrhBpESsERrQ
         0v+Eo+VF4eGscwh2QFIOTzlZkLK6DpUwS2bqU3gjCuRbyu/FYph6LyeudOEfnNaAfUAW
         VwhzBbc0SftsGy6NlgR8xvxk8WYvyiPw23w30sJ1ytHD+amzli9RPO8sM2D9cS/LtbTb
         XOrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p06i0vZE;
       spf=pass (google.com: domain of 3vbulxwgkcrmwte1wz7fz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3VBUlXwgKCRMwtE1wz7Fz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id p1si565677ioh.3.2020.08.01.00.10.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 Aug 2020 00:10:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vbulxwgkcrmwte1wz7fz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id d19so583434qvm.23
        for <kasan-dev@googlegroups.com>; Sat, 01 Aug 2020 00:10:13 -0700 (PDT)
X-Received: by 2002:ad4:4089:: with SMTP id l9mr7569682qvp.175.1596265812531;
 Sat, 01 Aug 2020 00:10:12 -0700 (PDT)
Date: Sat,  1 Aug 2020 00:09:24 -0700
In-Reply-To: <20200801070924.1786166-1-davidgow@google.com>
Message-Id: <20200801070924.1786166-6-davidgow@google.com>
Mime-Version: 1.0
References: <20200801070924.1786166-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v10 5/5] mm: kasan: Do not panic if both panic_on_warn and
 kasan_multishot set
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org
Cc: David Gow <davidgow@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=p06i0vZE;       spf=pass
 (google.com: domain of 3vbulxwgkcrmwte1wz7fz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3VBUlXwgKCRMwtE1wz7Fz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

KASAN errors will currently trigger a panic when panic_on_warn is set.
This renders kasan_multishot useless, as further KASAN errors won't be
reported if the kernel has already paniced. By making kasan_multishot
disable this behaviour for KASAN errors, we can still have the benefits
of panic_on_warn for non-KASAN warnings, yet be able to use
kasan_multishot.

This is particularly important when running KASAN tests, which need to
trigger multiple KASAN errors: previously these would panic the system
if panic_on_warn was set, now they can run (and will panic the system
should non-KASAN warnings show up).

Signed-off-by: David Gow <davidgow@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
---
 mm/kasan/report.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index e2c14b10bc81..00a53f1355ae 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -95,7 +95,7 @@ static void end_report(unsigned long *flags)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn) {
+	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags)) {
 		/*
 		 * This thread may hit another WARN() in the panic path.
 		 * Resetting this prevents additional WARN() from panicking the
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200801070924.1786166-6-davidgow%40google.com.
