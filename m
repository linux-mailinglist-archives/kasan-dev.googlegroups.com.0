Return-Path: <kasan-dev+bncBCKPFB7SXUERBOXR5TCAMGQECCP3BCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id D33C3B22761
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 14:51:07 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-2f3bc8c5573sf8886746fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 05:51:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755003066; cv=pass;
        d=google.com; s=arc-20240605;
        b=kSCgbpPNfApChbl1fjNIRAB5lXEGIV8StDVvSmUa6z/r9jMz5k5xhFEvg8x1Xy4s9K
         t+6WaaHuldsMwAe/lYRGLX/+YGTHv5AHQhwkQzfCc3aB69ssK+dsdH7/kwRDzEQSssxY
         dbe0MAWy98ib2VfhHzSbaj/OaL8Pyj+kOwL5bRSpbLejkM8M17QtlgfMHFAIftqtVcSA
         v51Dx0dxAstOd61294k5do9M8+k52u/316RNHRM5y7wjlYCEL9v+x1kGmGUI2JcK7Xsu
         Jz68NOO3C6pt8w9ztSEdwQTWqezqHMztfay0NBtwkrR+zLHBS4orXWtM5R/zS4npdFaf
         81ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZaTjpPAoVUkgasp4xer8LL/vGZ/BVooEYWJQEN1WEGA=;
        fh=eud0oZk/i345tIF4ge/+dzyJ2+sU6cBC37HGPR/xNYs=;
        b=RcYZouVyFGzBChLA+fmCXWqzHP/a7X8CKiYE1n066i1/DTgWA9b6y22RyWds3hqNbw
         5YISEvJAVmQTLFezniVevt3f0KcQjgOaZXnBGyDtqTwjCy6DqbQfbX4SqQWlK/e21rRX
         NNE06yxhizTcrN5MIFJcM8+4+RlY+us56EI0NTttZOhDyva+BS01EoOfZUTqcWLxx8c3
         nt/vcx0usr+6h/ATvCaGNgMpmiqcRm+2xVK9jqZ3XMgCSNvSgAje+aoqy4SHJnoOel1b
         Ys4/W2OYvCVpfGxfGAVFyCKOT4Rr37vqR9qeTbD3E9I97KJ36L6r2SMQ5AucyRYG4c0L
         JNGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="ahtF/NiW";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755003066; x=1755607866; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZaTjpPAoVUkgasp4xer8LL/vGZ/BVooEYWJQEN1WEGA=;
        b=pmTUcvYkneNUYXDVAu6oJMW+sQw4pNyamg2cSC3BaaGmlGHwTnyyDW+WILBDUS1Bm0
         OEcLyvlO9D2of+brSuWi7y9mnry0ghPUKakrOg+JQySjmX843wAzmEnI4WCccfong52m
         jfupjptsA/VuNA4ERSWppWU1nq4quSEhZygWkTW2n4FS0s7Z6/aewpMIrblDS7H5icJR
         Ar4p4f4kHF+Pj5tdMUrH6WvucHWxRU/5XoY6FRISPWEWNL3TfOh+8/1xTT3ApgpF+LhA
         bEGuhtepK8pp1Bxa8nB23DKcJIaXBuVI8eT8A4MvOiksVZVPBvrtb5IoOAGSdBovSaOl
         IZjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755003066; x=1755607866;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZaTjpPAoVUkgasp4xer8LL/vGZ/BVooEYWJQEN1WEGA=;
        b=T22M268bwnfKuNtXiqrLgzvVHjfPUdyc//a5+0WuWWy9mjVC753ZO9vBMHfnSSo+FB
         tXDrZdPQEZDt+co+ObB1NzA943KCzzbM6LH0l7ExXb9s0IiBOE2JkJIbKxcFGH64p1Bo
         yalADfmLfJJ7iGMnpBbEYhTVroQh18eAZ5z5MMcssmjnTS6d3c2bwcSSGkeQaUG6kP0c
         XYv/kI81LWjHLzOqYdlYmbHfJTbM8/aGd4ONrwHWJgT5aQ/JSS8c79WAjahOqbJOqNgm
         OkHBY9AZiNEyqhjUWPBH2xt8ae4rjn0pCf3QnOw0dzrGV1RBWJBwd6CzEZ00diypQIuQ
         QkDw==
X-Forwarded-Encrypted: i=2; AJvYcCV/q3xKtTVwGlcVlqJsq1h2G7xLa1A6UMjtRuQoW5Xuz58ZGg7Bx1eqJWMbzAzYs4E6Omn3Qw==@lfdr.de
X-Gm-Message-State: AOJu0YwloOe8nHelfjuXlkBpc4CmVLLN9RVZE+ZIawVFx9G45+MbXZE2
	x0aG6Plk9t6q72SsH7adUaTt8jTwyQuPG3E9rltqwRwwvY9R/kKNIExW
X-Google-Smtp-Source: AGHT+IHqI5Hbv27uW1fge5AkOruWNePyvMYTfsDX0IvnzUA7YFHiHklY2Q+QdD/AJTw+a9lfIzpYeQ==
X-Received: by 2002:a05:6870:c6a7:b0:30b:904b:c76d with SMTP id 586e51a60fabf-30c950efceamr2278461fac.29.1755003066305;
        Tue, 12 Aug 2025 05:51:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeg2cckVmuzQFeF0hAFjiE3l15BhQfDpcKaonQ6pj1FEQ==
Received: by 2002:a05:6870:d201:b0:30b:c2b3:2130 with SMTP id
 586e51a60fabf-30bfe6d2128ls3035077fac.1.-pod-prod-05-us; Tue, 12 Aug 2025
 05:51:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU5hnra5izjzg8irNZ7XgwabzB5hQGqcNwXkoqSgouERyo1ZyZMRSzpXDizAhjkFjpsTN7vr1FPWRg=@googlegroups.com
X-Received: by 2002:a05:6808:2223:b0:433:ff53:1b7b with SMTP id 5614622812f47-435c91cda17mr1681171b6e.24.1755003065494;
        Tue, 12 Aug 2025 05:51:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755003065; cv=none;
        d=google.com; s=arc-20240605;
        b=Chcqiak/hvsDmEiS9pCRMQn/XjFsLo+M8/SIKUbNWMP8hhnsoohhc+HnUbsdLUsKUX
         dGh/c1aBXWHqSv59IAgU7iQ0QAmzLUshN9NNKuPbCNAp3ZrOpO614IW0NTkTztYhxlqQ
         AOowqQlt11ewR2PjGAE0WJCGgEpcFv5jfAA1MMYCF9A7WHheorpLe/aDx+WzjVbvyA9c
         Ua/mcrRg21e4Xj6Fkzep+ZDsqUQD7+3CoZVZErQcmJpN1MQrtlggUcFyrqoF08dgQLU8
         GO7g4r0bl8/jv2EQvbGloAdk3MIreaxR+Ub3KsiMxDCFYhbCIj+bYEPSQR+E+CGV7eXY
         gD0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+hQAnfUidTkYrnmu4spIdiJcPf/3EYQSdRJ9OD5/zYQ=;
        fh=ZQiobZ3avnYd2dMV0+zhbhF+LZ041TMixvjrGLjsPak=;
        b=l2uGEAdQZS7o7uU1Nps7jIrtKYW2Z97CZiuNbAJAMEZgRA02VbTaPR5bO2fkNcZW5y
         7Jz78jiApNAV736eUSUPsMCFChR1ibtstELK6/6wfH17podjL8uSqbfM38cMXcWk7aKc
         xjuPLwU/Uo71uccq5O+YEhwwucNGsKcRmNmvy/JRlL4E0+D7dp5rODimWJ2NS0wKhjZQ
         UjDdCRlkfww81hUiiq4PhdT5icq0oVCD6KRHT5GW+ERx3BUUZPIyZmR0PBG0Jc+EPdii
         To7CxI9MDFYR7T7lm8obxOlyI+/95F/epwBjl/q1I3ai6ivBnOyADzHSF8u2gIGPWKW9
         pgKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="ahtF/NiW";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-435ce8efbd1si42833b6e.3.2025.08.12.05.51.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 05:51:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-433-lYRCxuF9OOOH8dMMXILcPA-1; Tue,
 12 Aug 2025 08:51:01 -0400
X-MC-Unique: lYRCxuF9OOOH8dMMXILcPA-1
X-Mimecast-MFC-AGG-ID: lYRCxuF9OOOH8dMMXILcPA_1755003059
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id D0B1B18004D4;
	Tue, 12 Aug 2025 12:50:59 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id A33053001458;
	Tue, 12 Aug 2025 12:50:52 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	elver@google.com,
	snovitoll@gmail.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v2 09/12] arch/x86: don't initialize kasan if it's disabled
Date: Tue, 12 Aug 2025 20:49:38 +0800
Message-ID: <20250812124941.69508-10-bhe@redhat.com>
In-Reply-To: <20250812124941.69508-1-bhe@redhat.com>
References: <20250812124941.69508-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="ahtF/NiW";
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

And also add code to enable kasan_flag_enabled, this is for later
usage.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 arch/x86/mm/kasan_init_64.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 0539efd0d216..0f2f9311e9df 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -343,6 +343,9 @@ void __init kasan_init(void)
 	unsigned long shadow_cea_begin, shadow_cea_per_cpu_begin, shadow_cea_end;
 	int i;
 
+	if (kasan_arg_disabled)
+		return;
+
 	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
 
 	/*
@@ -450,6 +453,9 @@ void __init kasan_init(void)
 	/* Flush TLBs again to be sure that write protection applied. */
 	__flush_tlb_all();
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	init_task.kasan_depth = 0;
 	pr_info("KernelAddressSanitizer initialized\n");
 }
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812124941.69508-10-bhe%40redhat.com.
