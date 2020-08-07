Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC7YWX4QKGQE4ZSOTOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id B597623F07B
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Aug 2020 18:06:35 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id u68sf858591wmu.3
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 09:06:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596816395; cv=pass;
        d=google.com; s=arc-20160816;
        b=f6w/uv04F43sYcS9pw2qeRiQ2o7mPK6KhaU4+lD+u3DWBfJL3Ec5zkkidR7W9itbr1
         HtWaT1fMGTG0ePsKT5a+NvquPM/obzrTRa7EjYy2miLSIEqdAkd2TPlQM5dsasB/wiEq
         wa9TRupU1EMRXKj4JEpoRildjzKJamWJeMYVGE+GPltiEg7/KcDi0BkcgHgqvrmM1MEf
         p7Ya0qzGHuMC8/xbD9jZLUuPa7ScMwJaESf/jMpiMB8QyD8PiqYNI6SZ4/P5xfreMAD7
         yX7jdrK0e/1v5pZC5r71G0iGr6LgXF+rH5ZkVmC1KqbJfQrTL/dYs0J1LvK8zFVVeSAW
         6L/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=JFRggZ45JtChvaaIwCVE6TCtYagKdlg1dyTJiDx3Y7k=;
        b=n+FL9UASOmfGY7BV2Ntp+7Zzfn74oAx/+jeOtuMydOQ0jbqplhI+D0LEdaJ3jWgypj
         u5HQxDszd84Yp/3M9OA0Y1qHUFknSQ2t2+gP0Ektk57Kp4sz5JnrlMx1bCqxR2s1GA/A
         M9U8wd8WJsp8gKuT1mN1EfZxh4mAHZDHR3/6YwyyOPw2IFko8rInKa7FpFM2fd5S7K/u
         BEzSXWwoXPdWLD+VJk/PDsG6YQoF6wtdHn64ApkjcgJ20YVM5jyld/TtzEAghHNlwXXs
         +0m19/c9Ic8k7Tb7QIDWjBnJDTnGi3G/v6WNYWi0dmpQ7ojbHJzZCSk9MXyGwkTkUFau
         3paQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Pv653W5Z;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:mime-version:content-disposition
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JFRggZ45JtChvaaIwCVE6TCtYagKdlg1dyTJiDx3Y7k=;
        b=GEybf/7gXd6YFmbK3eIBDG14nSdejtojaXzaKRnX1ZQz+xIe39qs/47VIyRWPMRR+Y
         8eT5pf5EPiaMtaPjFpx6qwXvKAT98KpLcG6OkW1mW2ZG6hDfn/BfziA63jXDFUbj22xN
         YKiZtGr+xiOzt5OmaOgN8+Ed3x+aK6E0cr8o/C1LGAxtFjS5VuaqO7E2QQUH2OkpY3du
         k4RBW+GY5dNURIbvzDiWk0AuRtrw+DR00N/0o2LRBCXvjdgX2nAG0iK8QAEkjCdlf0da
         a0xgVnvpqEoS8DDh6ozHMnla+Z9V2bryOFKepGgeaN8xGFQnqt6OIZDuXvSuLkknreGz
         aXgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JFRggZ45JtChvaaIwCVE6TCtYagKdlg1dyTJiDx3Y7k=;
        b=NfrjUIjAdjT/tGgXQwwtXmnnMx/ZVTxEeaGV0XUHo/3nQV8/rtuBQe+oVaKMHy+Oq9
         niU3FfNt9mWjJLMgg+D0P9y23bBox4wPwPGlb948JMeonSj6d9wflc530f2/fji6EbJN
         g0Jd5uIG74KRPNbCsLbDsFMocJie03LgBouZTsEbX3xuMKyONy8/ry+70BzpnyLQqyku
         3M2Zs7/fO10C7bSYh2XCvSUcxoNVX3UR+t64rW+bSiBEByCj9gsJopEkKgcMCUyji/J/
         8JP8rLpWNpzL+ONwBIQVmA+IVv3e1CM3sSX82mUl0F0mpZal4nyiJkRDPKlOOLzGvCrE
         FT9w==
X-Gm-Message-State: AOAM532rmsPgCzFSBc8Q3x4L64m9WbScvEvkSPodFf+NK1sDMpjNE81v
	8tYqfRj6kPVLaAOCjlkkfNs=
X-Google-Smtp-Source: ABdhPJwQeW4HQ9o1KJSdyI2un6ZHYR9Nc6RVMU6O8L6THNl7tXXh3TOpzVARdKV3o1DlhE7uiUM4lw==
X-Received: by 2002:adf:dfd0:: with SMTP id q16mr14024577wrn.60.1596816395421;
        Fri, 07 Aug 2020 09:06:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2049:: with SMTP id g70ls4721774wmg.0.gmail; Fri, 07 Aug
 2020 09:06:34 -0700 (PDT)
X-Received: by 2002:a1c:e0d7:: with SMTP id x206mr14519209wmg.91.1596816394855;
        Fri, 07 Aug 2020 09:06:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596816394; cv=none;
        d=google.com; s=arc-20160816;
        b=v8UTmIKD9ITgtUmo9HyzEqDR/nKb6Tjvr/8+Scx0E/8w7YpKsbTdIK0SyfJxAsBU8v
         dP+3XF8tlSov8ZZnLm/SQESIpYq81y7EYxfndXSPdjbfgc3BHQmT7d54IPzRjaIGF8+y
         4AQayJE74DWKfA7XE92g10nOS9JjJStQfdGo//Y+XZeHNVThUPqOWNtZ7GI8nXNFFDMO
         1Cnbxxrt+YesCxDQYX8+oSdp3eU1KiTTp9YSRfwg16wQJ0IKk+zpKXImFK78TatJQHvS
         cQa+TA6EAvbzdMnOy+6W2Ri/JfOFozrR67a7xXfzRd0ik/QZdz60VPff0y4Fh8AP1CIq
         P4nQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=lB0exDTiK20r9BbG9hUJ8sI2xKN99bAKX09J/wOfYgY=;
        b=r8sdmMy6ji3LLmRH8T5s6bkRnq7G6YDbuzxG5zC9enI8VlVduZoIn2M50584NBEuWq
         a0xQZxQL3cL2LPuRmjG/WF1mE3MaDRzGU3SCIpSDXS1B3x8dkWW05coPs51b1NocpsTv
         Iff/fBQTto7gCx42f2jO7ib75IQGiBiN69JX/Ei1/MkLtR+pK6xNO3hH4WVbMAz5gXmw
         iHV85oapO6t0k/F6tTfiIDiPwsaJ+Yix0vymoaq6Hi/P5J6miwUfpm+vgnx0TzpDb/XE
         hvWXA+uitcy3p4wGDrxLJW8mEtWHgthAU/eWl61auz+IupFeW+BXQL5RrAPnl7qYhGD7
         EY0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Pv653W5Z;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id m3si495935wme.0.2020.08.07.09.06.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Aug 2020 09:06:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id r2so2149003wrs.8
        for <kasan-dev@googlegroups.com>; Fri, 07 Aug 2020 09:06:34 -0700 (PDT)
X-Received: by 2002:a5d:4a41:: with SMTP id v1mr13852053wrs.371.1596816394436;
        Fri, 07 Aug 2020 09:06:34 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id t133sm18135689wmf.0.2020.08.07.09.06.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Aug 2020 09:06:33 -0700 (PDT)
Date: Fri, 7 Aug 2020 18:06:27 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, Christoph Lameter <cl@linux.com>,
	Kees Cook <keescook@chromium.org>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Odd-sized kmem_cache_alloc and slub_debug=Z
Message-ID: <20200807160627.GA1420741@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Pv653W5Z;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Hi,

I found that the below debug-code using kmem_cache_alloc(), when using
slub_debug=Z, results in the following crash:

	general protection fault, probably for non-canonical address 0xcccccca41caea170: 0000 [#1] PREEMPT SMP PTI
	CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.8.0+ #1
	Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
	RIP: 0010:freelist_dereference mm/slub.c:272 [inline]
	RIP: 0010:get_freepointer mm/slub.c:278 [inline]
	RIP: 0010:deactivate_slab+0x54/0x460 mm/slub.c:2111
	Code: 8b bc c7 e0 00 00 00 48 85 d2 0f 84 00 01 00 00 49 89 d5 31 c0 48 89 44 24 08 66 66 2e 0f 1f 84 00 00 00 00 00 90 44 8b 43 20 <4b> 8b 44 05 00 48 85 c0 0f 84 1e 01 00 00 4c 89 ed 49 89 c5 8b 43
	RSP: 0000:ffffffffa7e03e18 EFLAGS: 00010046
	RAX: 0000000000000000 RBX: ffffa3a41c972340 RCX: 0000000000000000
	RDX: cccccca41caea160 RSI: ffffe7c6a072ba80 RDI: ffffa3a41c972340
	RBP: ffffa3a41caea008 R08: 0000000000000010 R09: ffffa3a41caea01d
	R10: ffffffffa7f8dc50 R11: ffffffffa68f44c0 R12: ffffa3a41c972340
	R13: cccccca41caea160 R14: ffffe7c6a072ba80 R15: ffffa3a41c96d540
	FS:  0000000000000000(0000) GS:ffffa3a41fc00000(0000) knlGS:0000000000000000
	CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
	CR2: ffffa3a051c01000 CR3: 000000045140a001 CR4: 0000000000770ef0
	DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
	DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
	PKRU: 00000000
	Call Trace:
	 ___slab_alloc+0x336/0x340 mm/slub.c:2690
	 __slab_alloc mm/slub.c:2714 [inline]
	 slab_alloc_node mm/slub.c:2788 [inline]
	 slab_alloc mm/slub.c:2832 [inline]
	 kmem_cache_alloc+0x135/0x200 mm/slub.c:2837
	 start_kernel+0x3d6/0x44e init/main.c:1049
	 secondary_startup_64+0xb6/0xc0 arch/x86/kernel/head_64.S:243

Any ideas what might be wrong?

This does not crash when redzones are not enabled.

Thanks,
-- Marco

------ >8 ------

diff --git a/init/main.c b/init/main.c
index 15bd0efff3df..f4aa5bb3f2ec 100644
--- a/init/main.c
+++ b/init/main.c
@@ -1041,6 +1041,16 @@ asmlinkage __visible void __init start_kernel(void)
 	sfi_init_late();
 	kcsan_init();
 
+	/* DEBUG CODE */
+	{
+		struct kmem_cache *c = kmem_cache_create("test", 21, 1, 0, NULL);
+		char *buf;
+		BUG_ON(!c);
+		buf = kmem_cache_alloc(c, GFP_KERNEL);
+		kmem_cache_free(c, buf);
+		kmem_cache_destroy(c);
+	}
+
 	/* Do the rest non-__init'ed, we're now alive */
 	arch_call_rest_init();
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200807160627.GA1420741%40elver.google.com.
