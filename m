Return-Path: <kasan-dev+bncBC6OLHHDVUOBBX6CR34QKGQE5V5NRXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 732F6233E6C
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 06:43:12 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id k72sf3706451pjb.4
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jul 2020 21:43:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596170591; cv=pass;
        d=google.com; s=arc-20160816;
        b=KDrJkz7fuFCjJSpxkD3amkO9p+2FN6Dc70U6+/W3twS5oNQdS/0365ae5nJfznYlyH
         Wcpjlp/5W8bycZSjbUYyFS2Lxm6UjoXhQn7p2twccYtwteZUqU5/5DsO5hq0g1WyvtB+
         ZXLb8+ht3dtummSMDUatou+G6IQKQNiGWCI44DpM1UQ+9CT4G4FTM/sAWn04bVbpi6dg
         7yO8XcKwv9oj2YuyKHop4TAo3hp8e9mxMydcSfKL9YBqXDdS6NEi0ETCrYBQfS1hrq4c
         cwnnej7m60zIAFyh/2meKnpcRKUcwrdyybuNQWFwXS3A0RwdYVhsypUynGhn+aUVb38R
         ApUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=XwbZI9Uw3RWSHMyG1JuP6AGV8bL5DFM90qu2g+5Ism8=;
        b=M0gvcz04h4vNhCPkY58O84kkJ+iyfgvKBUBGymMyi2i9cs12j0tLgTiyK8WFTaBp70
         BC9eH+XE4MDF0utMtgH7TqyoJT9+uQV4sDuWgNVuze9s3Bkfh5SWv7V4GGedlmhVV5Hr
         Dphp6xJekZSvb1bqahffv6KjSlgVvP9OdxLhjjum28GuPhnVilmWCOnR7DNMOLbF8aLj
         /n9/9v82/glXfyxgxagb+Pysg1jQl3Hsz2YaLkyfiyA3u3sSR8VXHki7X9mVVkdcX9te
         0aSez7nnvVSrpiKUtJzz+5sfLsKT2DtI/CFHKqe9ENtvJjzzOmpY5Dln8z9J/vWKXTtj
         ZZuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nM1Ko5uZ;
       spf=pass (google.com: domain of 3xaejxwgkcs4nkfsnqygqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3XaEjXwgKCS4NKfSNQYgQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XwbZI9Uw3RWSHMyG1JuP6AGV8bL5DFM90qu2g+5Ism8=;
        b=HeU1CRab0xzK91FpZF6GFpdZjeys9FE0rWQN4Uu2z+VmpVMFavHkV6ymLMWzY74blK
         EnnxyVcc+fC0kJTmHReE53UCrZCESppOHJT+9nkfO8u1UPnbBd+NThqugNrusXPMCfDK
         LNAvUh/qxlv0a6WuT0mNGlWJvyN8QNM9EN1eKR5V6J1v9+A2vDDJZdcw99xpd6iIaXGw
         X0GOB6v7TBhYjB8jbkXfr91SWJpz59yoMRDNNHp6mOD+/4odJCHlIUKuPP2frcV0TLFj
         ukxrgY7LIgtazq2ecZ9Y85bmWFyd2GbkTDdl38i6jEIpRyTpdN7b/VBqFrFpC0hGQtSP
         hHcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XwbZI9Uw3RWSHMyG1JuP6AGV8bL5DFM90qu2g+5Ism8=;
        b=ZJK6Rn547EEUcoNr1J6Cs6AI42X17T6IrAw/U0P0kFnG5QW77rsJmzT2D8T0xOJttd
         nRqK1njJ8VT48ZOKozSB9Mc/C/iaRBG36Atdlcjp+NH/XVCHaO59Ifn6XS//3vN5ziWw
         CCGw9z1+fa8rt3q7Z5HifaGniaWGeFqx9IoDybhRr06qXcwX0fJOuhjNYFYdW6Mn2Xwa
         VrcpKhUmMI2zUzXLNGAntdMmIEXWr04gV/uR3UJhBAkBkCnBAzE7ZnG3nmJbsCzCY2+I
         RkFO/aIE8xnTyHD4GOdNJ6K8H+KUh8q1G3KwalhkY6fo4Zi1QfAqh23hckVNP2oafkX6
         vUPw==
X-Gm-Message-State: AOAM530pwMOIRrXgbocQIVYqFTfVm90zLkh/1RE+nTdOzFY+Dg987Nmo
	eAH3NwNqqXlyL4ssBZMfLnc=
X-Google-Smtp-Source: ABdhPJyxXAYUIDm80brFkFVI1uA/dyg5RhfPWetIp158ZHIGre4Mb2vY+IHyJ2hOuQV9XgwBT4YffQ==
X-Received: by 2002:a63:8f08:: with SMTP id n8mr2120872pgd.9.1596170591198;
        Thu, 30 Jul 2020 21:43:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fa93:: with SMTP id cu19ls3215174pjb.3.canary-gmail;
 Thu, 30 Jul 2020 21:43:10 -0700 (PDT)
X-Received: by 2002:a17:902:ead2:: with SMTP id p18mr2108023pld.339.1596170590750;
        Thu, 30 Jul 2020 21:43:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596170590; cv=none;
        d=google.com; s=arc-20160816;
        b=WZrvh5tVSOwyCjL8+KV/1xhZ6+ly7k/kEi/30gNo/XtgN9UkgLig2zQL3tUp6BAMoJ
         AFENQUrOX+v/OXSnlUMXkSVLWQ2GlcqMoM/H1quw+MIleU2nvzcjiGYc5YTp86/Wruu4
         LAfMlSR5hWzFxaFD1tf/yaUO3QgkTznVTFcCxZD0g8PwDOl9g3uXAaCupe2zerNYFsnn
         FHjQbmy27NomVZmfCMiOMtVvNN+2FhVeYE/yTeyAZoR+3lo4SW7F8GsnBn7QQYhh425h
         mA9FTID5kljeMIdCNkMjtW7B8eXcg3zk1M+XMnugJTEZBMYZN6lgO4CdifHEw2jk1u6r
         CrNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=85loYESi4Z2DrhOdMAtj0xQZzuVg3GU4Cjv9w5JgQ2w=;
        b=ugi7dKBTTGK8/fyl7axqfdbfEuWUnZ3yjqGeFdJGh0U1bKZR4BsJQQa2UsZ7JgzSZM
         oJo1xtai17JO0FtmxsqY2HK8hZZMQSWqFp9VZb6FWCptfVK4NbYHsOv/95O9rs91Z1bn
         sAk+vcbQqfPTnw9wMlAL18JnpyQIO8TjP6ZhCArwbmyR8+wN873HVwZ5h7U0NfSYLhWQ
         0TdZ9yNMJrxkCnw9khkuWoWWEIR+4zFyE8l9Hk6HHUrcozYtiq72B/oT1GfiI1aCMtBH
         VxIEuUr+Zdp930REUDWxRyjLeAmq8y8l+8T/HUFR3vP1/f/SWURH2e87GEb/S6UB/fEk
         b5wA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nM1Ko5uZ;
       spf=pass (google.com: domain of 3xaejxwgkcs4nkfsnqygqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3XaEjXwgKCS4NKfSNQYgQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id z72si520586pfc.5.2020.07.30.21.43.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jul 2020 21:43:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xaejxwgkcs4nkfsnqygqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id p138so13130843yba.12
        for <kasan-dev@googlegroups.com>; Thu, 30 Jul 2020 21:43:10 -0700 (PDT)
X-Received: by 2002:a25:e5c3:: with SMTP id c186mr3565894ybh.332.1596170589932;
 Thu, 30 Jul 2020 21:43:09 -0700 (PDT)
Date: Thu, 30 Jul 2020 21:42:42 -0700
In-Reply-To: <20200731044242.1323143-1-davidgow@google.com>
Message-Id: <20200731044242.1323143-6-davidgow@google.com>
Mime-Version: 1.0
References: <20200731044242.1323143-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v9 5/5] mm: kasan: Do not panic if both panic_on_warn and
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
 header.i=@google.com header.s=20161025 header.b=nM1Ko5uZ;       spf=pass
 (google.com: domain of 3xaejxwgkcs4nkfsnqygqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3XaEjXwgKCS4NKfSNQYgQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--davidgow.bounces.google.com;
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
index 90a1348c8b81..c83d6fde9ee4 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200731044242.1323143-6-davidgow%40google.com.
