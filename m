Return-Path: <kasan-dev+bncBC6OLHHDVUOBBNFL5T3AKGQEAXKM7DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id F085F1F0493
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Jun 2020 06:04:05 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id y5sf10449526qtd.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Jun 2020 21:04:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591416245; cv=pass;
        d=google.com; s=arc-20160816;
        b=I97Y7/rPsiMT8dOTaJpPG646yp9xR/fDY1hvd1ZCQwAdr9y8W3xPZKvulrrM/TzcsP
         iy1m7RVQpZ/XV2pKFaGoaxwdBblMqjdCnXotAKQq+KlDvTlQg7ZTf+xdgVDFQLlaKX4K
         FlaCuV89ZOL7FC69jYcROM9L4SU3SOdQjs/OTmsrgBALtOxLGXK3yTXxT8VZ1oOm+CG5
         C2ij6MpZ84LEbpFnNJKvq7qiWPLRbe6eOMGNOiNXvrQJWkUSVL4PnZ0OPm/0wqnMg4sQ
         MRv6Ru+sGKIlRmGyFK0MURQp4psFF5KdNsQB0U/sze1jIzPjufdNy1BQUJYMEyV0Gg/d
         5ecg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=9mY77gBdrjo0HE2gboJP7d8AO1kCGpZX2XAET32Rdkk=;
        b=MIAmOqvxB8cFS2nNuM//jivOQ62ZM7WwiIgqcSXMp8bjy1ILIvIg37lrUfh8+/WCfJ
         XJcGyTBDCD4vlze9m5worCvG/Vrm28y8iLdk32KW41RjiWBPLhZ2SzxgWgfERjribZwd
         y4YqQE9mVIOzMuUtUA07038bnOOABIuFHEsN0VkoNBg204kdKAEe6Jl7XOAXbXhcNlOC
         b+VlyL+ZRw9PL7A6x2xQ7C65vADSFeXxk96kjMfVGsTtG2kmQx7h8vQST53CWAmSpF7n
         FDgLnSjBGdZL71dt+b1hPN44mrIP+cRIlMahzkWycDFbJGYI44bGYQSm7iUjdXqkTjuR
         O6Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YHJ+OxXk;
       spf=pass (google.com: domain of 3tbxbxggkcukol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3tBXbXggKCUkol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9mY77gBdrjo0HE2gboJP7d8AO1kCGpZX2XAET32Rdkk=;
        b=ZHWWR9vqNNxcqaJ2xK8GVTBk0WpUyiMKENB250muHpbvV4vVu2zbB4yfDWyZMluZOv
         rwIl6V0TWSk0dEql6/rueK4moB2JZODqeZhzR5GyjNoxr5iLkBbMPHGzuTPlM0pI88Sl
         BuYfX3u5+6torljFkz/2z0hUR3Ev/Qp6raJKhF6tUDGWWR7rsY9Uiq52FOm8MN0cZ07T
         2PuFaL6GC9Owu8Vf1hDXdqmSvSCNkHLbjIhd5wW4iSrnvVBhkFVwRJ7Qi98APoBdZMjD
         5tA3SHe7pElP9dTQhV+FUIfa0uSCpMcvom7KyXecPlA+jc3TD1MuivpIA/IaX7gqY3Gy
         giMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9mY77gBdrjo0HE2gboJP7d8AO1kCGpZX2XAET32Rdkk=;
        b=NJGHXYX7rzDfQQv0moRjXYz95BQ94V4dZVI7rYri4tl8Z6BoBdvNA/XrmANE1AKBYu
         WOPJgcCYxXU5K9320OS0ROrJdXD8sR77n1UwQX8CnSki+JPC5PulZe29ZWTcFRQM8sgI
         fmpQXxbxbIhZMDV2yLGFQz5q6BDeCj6QmyjGJ9Sa/Rw0+yEF9+gvX03IesAKl6/qLWpg
         OWNTgRRHFDap2Vf7Mg2xh/AMeR2NkT55mIJ61bCtBHmq1xZozC37ghWwHHr5vJGeEbyd
         OLI92X+2ETsOcU1Atu+GE3Ak6EUq7e7y3LFq0FzKbY4eQ7aAE+R2O/VYuvfhLq/+smoY
         wTWA==
X-Gm-Message-State: AOAM531scTuKEFkMEIY15grbapT0SL9ZvbdRLSynyYTS7IulTSpKVe/6
	vqX9iHoDJkpd0viwX0eryb0=
X-Google-Smtp-Source: ABdhPJy6bqpKlINkmuG8hAVfPVfGQWqZB2gsIZ1zkrDRBWIGzw8/4PhDbH+LQWKp2ezZxxhli0VsrA==
X-Received: by 2002:a05:620a:2290:: with SMTP id o16mr13308537qkh.205.1591416244803;
        Fri, 05 Jun 2020 21:04:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:ac7:: with SMTP id 190ls5427985qkk.0.gmail; Fri, 05 Jun
 2020 21:04:04 -0700 (PDT)
X-Received: by 2002:a37:a74a:: with SMTP id q71mr13353801qke.446.1591416244481;
        Fri, 05 Jun 2020 21:04:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591416244; cv=none;
        d=google.com; s=arc-20160816;
        b=XFUTpATjfUQncO36b2za2OLSTFURy3pKTTj0Kh4FAD98aKp3pgKFHMtE727A+At1WZ
         plVUfp0jG34tsOdpJZ9jLCJLhNSc+Wzo9PTylun/YdL9MC6XKIfoXEBUv545nbEW9KML
         M07yMku9kZ9uJSb9TAXz08+ihatU/iWHh/3Ehx0rqpQtythlCSvYxLyXfoswEYfIlWIe
         qU0q9VaQhkmbc0zePh6h4K/HWPgYWdvJtQIhW8YE2RaEGJ+EKGrSz4qe9Kg7qD2NGcVF
         /aBZbD+uQ4rQQ5jmRZFNEihcycxWPKFfkMqFbm5hFkOGSkTllLytb6PmoA1L84J44hHx
         1ang==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Bno6lpmXJK51n5a5Nx8tNY64fz3MIJ1lkOtErirSr6A=;
        b=URNlapx6DrKsqDa86bIsEWe4H0OB9YBHQasLL23vTvOdY2DjtVk8aHrVA9nK2ws+HQ
         SIiLfXtUxaQVAtERJBC60uUYnZbwTnm/8CjVwwPmBTp7cviRMiaGKh8WCEng+XVJZSso
         fwihypJafKpZpArVWF0ybriBef20T2qQTFPy+9O/aGgXdMBA62g9+oltGJa1EukwJghk
         a5DWy8NaOceGOltcIyyD3wH+CjrR9X/qCjnsrG4UOQM6Q8fQXfBhFVng97P3hbm9pCyL
         iAKBSGdpr2jHrt0i+N6NvaIPRkoXF3c/5a410UJUpU/IZmuv53vYASaSThvQC+w/zdeF
         h79Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YHJ+OxXk;
       spf=pass (google.com: domain of 3tbxbxggkcukol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3tBXbXggKCUkol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id d64si44718qkb.0.2020.06.05.21.04.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Jun 2020 21:04:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tbxbxggkcukol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id e192so14231675ybf.17
        for <kasan-dev@googlegroups.com>; Fri, 05 Jun 2020 21:04:04 -0700 (PDT)
X-Received: by 2002:a5b:785:: with SMTP id b5mr20722587ybq.96.1591416244078;
 Fri, 05 Jun 2020 21:04:04 -0700 (PDT)
Date: Fri,  5 Jun 2020 21:03:49 -0700
In-Reply-To: <20200606040349.246780-1-davidgow@google.com>
Message-Id: <20200606040349.246780-6-davidgow@google.com>
Mime-Version: 1.0
References: <20200606040349.246780-1-davidgow@google.com>
X-Mailer: git-send-email 2.27.0.278.ge193c7cf3a9-goog
Subject: [PATCH v8 5/5] mm: kasan: Do not panic if both panic_on_warn and
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
 header.i=@google.com header.s=20161025 header.b=YHJ+OxXk;       spf=pass
 (google.com: domain of 3tbxbxggkcukol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3tBXbXggKCUkol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com;
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
---
 mm/kasan/report.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 45f3c23f54cb..dc9fc5c09ea3 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -94,7 +94,7 @@ static void end_report(unsigned long *flags)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn) {
+	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags)) {
 		/*
 		 * This thread may hit another WARN() in the panic path.
 		 * Resetting this prevents additional WARN() from panicking the
-- 
2.27.0.278.ge193c7cf3a9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200606040349.246780-6-davidgow%40google.com.
