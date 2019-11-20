Return-Path: <kasan-dev+bncBDQ27FVWWUFRBPU52PXAKGQEWVLQYTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id ED2801033DE
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 06:27:27 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id t23sf21589968ila.19
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 21:27:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574227646; cv=pass;
        d=google.com; s=arc-20160816;
        b=hShug/NEIMkN93A20+vFJA/rlk7L7HZMi88Is138sgSDgdk40UMsh66TovyN8gajrO
         6X0qzgLDnF5nqJXoO4MfggMNDRshOvQrX6LSmWoNamyMD1+iCeBFcNodOqzNH498Jdci
         ci+tB/U16tMnqn31/Br6gQHn9dJvi/gLF+cfUDobO8hgh31x5betjHNT1hWnh/Ql2N9i
         3hg77eaIc5SskhLLRl9U8Y24wisd5vjDkrV6JZKHYggdCqBqhBQ/1ruGP01KVRZhYDo1
         sHrKuI1BkVwwZzOGHBZjvr1EFW5z8M+zvKY3jdQX6VVkXYS3UeM8VWPaG4cu23gNbH04
         n8pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=PfnN6ue782hBak8h8lJ8zMbDUOnIWRikMS5JFdNyKn8=;
        b=nh+1EslP72EzqUGUByfc5+z7+2Q9ZGcO3+Twxt/XvzJZQp6vmDZXrfn+WsyU42bzBR
         ejF3qjuBydIyoN8evqAh+DZxH0gH8ygJcE/vdr0AyDZFfMBPvOvhDHQG9opV6BfpHX8m
         tsgwHDlGI6nvUONuX16uVdsjg00Tp7daOP8ZrgVF5gYlSp6fkiaSkNhSORDYG5rwiyL9
         KNnNaBgOqEaOIDKkkGdKnI9kLviS72Dw2/mmbQ83tifFsDowKNEswzkb+qqX4HF3543d
         Ttw77EHpnxqARCSLppmX8a2UN5cnYlkVgcbQaJglGmuiV3gr/DlpUzx5lH8bNhWfnk1C
         o5Lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ETA60fcE;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PfnN6ue782hBak8h8lJ8zMbDUOnIWRikMS5JFdNyKn8=;
        b=eHRu7C4LzrDuiLEfDj/jwoaRrhnparQmcoB3D3FJnUDihrjIhBpdVMczRlfF46oJLL
         IQgz7Ed7yY3OWje3wzt0kaZiX0TdCW5h+XTnUjRIf8l35SlQnwmjGWY3znxaotBU4Pup
         QJKMolkjHfjDNbXXjyJwuwOAzaBtGbR1nMdOluYquYyCAFsBtWDocopzcAyug+1h8+cV
         rKCwxckjG6b7dik3D9/ySQ1TohrIYngS0VNgJYPK6CrQ8CXiVhhLmuMRHSVCDqD1jFvO
         nwboO6KLOPw0Qi3Y1SVS/ZR2UndU1tkg8/JtZLmDgIljqPyJXw1JFsmM7bxPkbzT0viW
         SgSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PfnN6ue782hBak8h8lJ8zMbDUOnIWRikMS5JFdNyKn8=;
        b=CZak5Oh7EJHFusqIURJedRInTAYKTMf9B7ElyGq+/H1FnzSZoEiXlTw55u6vfNPQoU
         N1ZR8HxaebUFvFJdUquuEyEBcqEvg9A2AVr7mVJUmMPW9DO6kJCwVqoJahcB7SLEhOEW
         dildWlW/AgqfVfa5p9ZLuY2MDaRzbj27xRncbYTeHyLn7DHCxSsccQu85bN3Dkne+5yl
         NmLdDkYy1j1Ngci+aanz3+js/koCCwBcS04nUcLf4EOXKbmz91oUowAYipKUX9qDKffc
         R7p0x8il6d99QcTm7zfn3U9+F7Dh6A1U+whkGemWuRIVzScrB5djzbM7SQ8wnd0s3KWH
         W6Ig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWdzkfQJVV32/OgzgnbZoEvekjp1a73RYRxpw2vEFfhi5zF9+xT
	m8Lg3vdjVuvr8x7XrQQeK2I=
X-Google-Smtp-Source: APXvYqyQuFSEjdcCmMHRgYWIQyCRodDJLB+Wa/NIunH5Y0UUQaZgEbbSAcNRJAdfVJ6aT4qjRMJ60w==
X-Received: by 2002:a92:395a:: with SMTP id g87mr1646826ila.206.1574227646521;
        Tue, 19 Nov 2019 21:27:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:9e06:: with SMTP id q6ls182404ili.5.gmail; Tue, 19 Nov
 2019 21:27:26 -0800 (PST)
X-Received: by 2002:a92:5cdd:: with SMTP id d90mr1707858ilg.48.1574227646113;
        Tue, 19 Nov 2019 21:27:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574227646; cv=none;
        d=google.com; s=arc-20160816;
        b=KOAhlznIybYM+a0MJJsr5O7l38wW2rCCtZO6UvkSg1nIG+k3FbMPJCDrG0vJgYJ1wi
         r30v1Oku2uIT02jYi4p/h+vK9ugxO6iqgEp6j0gBNummy1FK/O/OB6JgyEHeYiOzuQOl
         SdCNO9+gm8BD/huOIkD7JUV5lUr315rj5/7JswKjir6RXor537Gyv2hPwofhDOnVZPRn
         vhwh31bDa5bHRs7cHeONXeQPv9fweh1ccz3hBNSFmpQCb28Wve5/V+9+w5zLfdxHCyYg
         +d4Ahnba0NAZgupmSC9Hptuz5Z3Ziccnwtqd9/JFaySwKhLv5MkieEV1VFmZ5IRjVzxg
         XuBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=keeeAI8Pfb2Kl/duSqjRgQqa9JjQMfYjDPW+Gc6NiSs=;
        b=iUHU2IO5zP+XgUGGQN+ye/X/8iZCjr5Ww7JwOyLoi0fuRVi3ygVgD0WPyJ/KHzqVxA
         6IHBTrZrWrmDy9DoE6UeEb5wm6rquzAIDsbR7rehm20yX/eOcpdrVUunrLYgZNuTwy+7
         mSa3lki0sNv/wiF7A8lPJUo0rjBJpgncGa1DF2goZ7dCWJvyg0Nte24GRUOdvx9mzmXD
         yclLL5cifi0+t0h14QtZuyLCHFgvxINfQHE1yFpXgbfDmRYfLYPQk0nfYgtgL7YOf2bQ
         qN1zF6+Ch6QrtDx7RmPSHNtGEWcBbxikZN/T05qpDheGBeTJf2IczEc8lUjEASM0qJjS
         sIUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ETA60fcE;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id z78si1422769ilj.5.2019.11.19.21.27.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 21:27:25 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id n13so13640184pff.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 21:27:25 -0800 (PST)
X-Received: by 2002:a65:67c7:: with SMTP id b7mr1058249pgs.339.1574227644988;
        Tue, 19 Nov 2019 21:27:24 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-9c57-4778-d90c-fd6d.static.ipv6.internode.on.net. [2001:44b8:1113:6700:9c57:4778:d90c:fd6d])
        by smtp.gmail.com with ESMTPSA id w15sm22333601pfi.168.2019.11.19.21.27.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2019 21:27:24 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com,
	christophe.leroy@c-s.fr,
	akpm@linux-foundation.org,
	urezki@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	cai@lca.pw,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH] update to "kasan: support backing vmalloc space with real shadow memory"
Date: Wed, 20 Nov 2019 16:27:19 +1100
Message-Id: <20191120052719.7201-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191031093909.9228-2-dja@axtens.net>
References: <20191031093909.9228-2-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=ETA60fcE;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Andrew,

This is a quick fixup to patch 1 of the "kasan: support backing
vmalloc space with real shadow memory" series, v11, which you pulled
in to your mmotm tree.

There are 2 changes:

 - A fixup to the per-cpu allocator path to avoid allocating memory
   under a spinlock, thanks Qian Cai.

 - Insert flush_cache_vmap() between mapping shadow and poisoning
   it. This is a no-op on x86 and arm64, but on powerpc it does a
   ptesync instruction which prevents occasional page faults.

Here are updated benchmark figures for the commit message:

Testing with test_vmalloc.sh on an x86 VM with 2 vCPUs shows that:

 - Turning on KASAN, inline instrumentation, without vmalloc, introuduces
   a 5.7x-6.4x slowdown in vmalloc operations.

 - Turning this on introduces the following slowdowns over KASAN:
     * ~1.82x slower single-threaded (test_vmalloc.sh performance)
     * ~2.11x slower when both cpus are performing operations
       simultaneously (test_vmalloc.sh sequential_test_order=1)

This is unfortunate, but given that this is a debug feature only, not
the end of the world.

The full results are:

Performance

                              No KASAN      KASAN original x baseline  KASAN vmalloc x baseline    x KASAN

fix_size_alloc_test             662004            11404956      17.23       19144610      28.92       1.68
full_fit_alloc_test             710950            12029752      16.92       13184651      18.55       1.10
long_busy_list_alloc_test      9431875            43990172       4.66       82970178       8.80       1.89
random_size_alloc_test         5033626            23061762       4.58       47158834       9.37       2.04
fix_align_alloc_test           1252514            15276910      12.20       31266116      24.96       2.05
random_size_align_alloc_te     1648501            14578321       8.84       25560052      15.51       1.75
align_shift_alloc_test             147                 830       5.65           5692      38.72       6.86
pcpu_alloc_test                  80732              125520       1.55         140864       1.74       1.12
Total Cycles              119240774314        763211341128       6.40  1390338696894      11.66       1.82

Sequential, 2 cpus

                              No KASAN      KASAN original x baseline  KASAN vmalloc x baseline    x KASAN

fix_size_alloc_test            1423150            14276550      10.03       27733022      19.49       1.94
full_fit_alloc_test            1754219            14722640       8.39       15030786       8.57       1.02
long_busy_list_alloc_test     11451858            52154973       4.55      107016027       9.34       2.05
random_size_alloc_test         5989020            26735276       4.46       68885923      11.50       2.58
fix_align_alloc_test           2050976            20166900       9.83       50491675      24.62       2.50
random_size_align_alloc_te     2858229            17971700       6.29       38730225      13.55       2.16
align_shift_alloc_test             405                6428      15.87          26253      64.82       4.08
pcpu_alloc_test                 127183              151464       1.19         216263       1.70       1.43
Total Cycles               54181269392        308723699764       5.70   650772566394      12.01       2.11
fix_size_alloc_test            1420404            14289308      10.06       27790035      19.56       1.94
full_fit_alloc_test            1736145            14806234       8.53       15274301       8.80       1.03
long_busy_list_alloc_test     11404638            52270785       4.58      107550254       9.43       2.06
random_size_alloc_test         6017006            26650625       4.43       68696127      11.42       2.58
fix_align_alloc_test           2045504            20280985       9.91       50414862      24.65       2.49
random_size_align_alloc_te     2845338            17931018       6.30       38510276      13.53       2.15
align_shift_alloc_test             472                3760       7.97           9656      20.46       2.57
pcpu_alloc_test                 118643              132732       1.12         146504       1.23       1.10
Total Cycles               54040011688        309102805492       5.72   651325675652      12.05       2.11

Cc: Qian Cai <cai@lca.pw>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 mm/kasan/common.c | 2 ++
 mm/vmalloc.c      | 5 ++++-
 2 files changed, 6 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6e7bc5d3fa83..df3371d5c572 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -794,6 +794,8 @@ int kasan_populate_vmalloc(unsigned long requested_size, struct vm_struct *area)
 	if (ret)
 		return ret;
 
+	flush_cache_vmap(shadow_start, shadow_end);
+
 	kasan_unpoison_shadow(area->addr, requested_size);
 
 	area->flags |= VM_KASAN;
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index a4b950a02d0b..bf030516258c 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3417,11 +3417,14 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 
 		setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
 				 pcpu_get_vm_areas);
+	}
+	spin_unlock(&vmap_area_lock);
 
+	/* populate the shadow space outside of the lock */
+	for (area = 0; area < nr_vms; area++) {
 		/* assume success here */
 		kasan_populate_vmalloc(sizes[area], vms[area]);
 	}
-	spin_unlock(&vmap_area_lock);
 
 	kfree(vas);
 	return vms;
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120052719.7201-1-dja%40axtens.net.
