Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTGWYOBAMGQEBS7LFNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id ED12633DAFF
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 18:30:52 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id j21sf13794028ljg.18
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 10:30:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615915852; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ouzq8J6gHiOgLPHWm+5KCCJReAQJ37x+EkTgfxQZXQNRphj3v64HkEzu+CunaTysui
         8eV3iB4jD7SG09w2sYXHbpZf84ZsPN8V6glWiY9LoYHtc34cutqRdjwDX8necSxcM8Q3
         jUh32tJKSvQ5GFFevgsfDb1GbOAll6Kgk5EHvRBuCxYYKd21DrYhxjisvxmv9/zDWWVc
         EZX/uq9stDS6OtzDNn0hZWNzAoXwFui35pxC5MA6xdQVTk+mCadvLKkxb973j2y2ETbb
         IliinNiORK2ND77C8SrwClH155mZ/tJFDUcCulV5S5Ljl75x/I+Ddjwpc8/i4AUdLqs0
         nXdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=FF9rJysGqIvZ3b/074vzTp65i66jH+pnNL9PZ81141Y=;
        b=R+okTs6DwLV+79TYcJHuh4E6dyqCWsZpJsHm+36HGWjrIWj+UTjm16aiE770sAG/F1
         vK072Msju6P7fejo4fpl1L4Sq+NzPh0QorTs7qrn0g/hqRIng5JkdCO4KkQNZwOsyu+w
         CLOUzwJixDpZIs5xQyhYUpSe57kSFFyLcXkJ2T2784PezbTV6ow3T2OYYc8/oYMKvxX5
         nw3+Fd+301ssgglEIzxHZt5Dfky8ecc+gaue4ilvfOdB+q+L6jkmqdh3+hb04N+lhfyM
         w8pDou9Dqb5gMs/eHso6Juye9kEwvPGLDrny1M8TuJCxnOFtySxwfNWQMUILgH/DOUc7
         t5gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Z678/QuL";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=FF9rJysGqIvZ3b/074vzTp65i66jH+pnNL9PZ81141Y=;
        b=Nd0f4ssOhGlOVQ38sOw5hMwRBHEw9bUwipLO3N07cPtJmzNhKFkpJmad3/ziDBh2uR
         zVOuA51uLp5os5+plHBGjm/F79KB9wDyDQywrXhD55iU/J2tD0qiIqQq0oXCyHG3c5Yi
         JMNq8+Mz/NokwUWu95W6Sz/svshKH1bzOlGg8huU5cUHdPbMS1e3fvu2xN7XCEfI8itL
         ErNGE9P4eqrDF5HWhyHCpVcz+10fPBvEmxtsQzo6IWzgaA/MDEfm87c47p+VTpyrK04+
         3Qa0oLLw9CzXbJQKGog+4JIZBooZvtvCrW9OyzWv6npOzVpadVcPQ+Hn+d/PFG0oYO6v
         KJEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FF9rJysGqIvZ3b/074vzTp65i66jH+pnNL9PZ81141Y=;
        b=Dyamy/aiM8EV9+cOlk77hqL4ECINe2rfHA8DzDHRRuyl7PRiVILP1zTykDw63pZJf8
         gmRNAbovX0EqsLByY0GpEnc5vUUu+pUk8qUktK5D9vvOWVVmyX9yc0b2EOIMH6Dio3Ct
         6OKQP95414ViOyb1BxgnyND2v42BfTym87Oei4DO7APwF0zBCoAgy/MxwxnkB4ESjWu6
         w805fKRnSS4MkPRp2wYAedWHM6l2weu8WojtO1lTxay5HhQutQvV8V3SeUuUpA7Rep94
         0fc4wqD5yNvQlxWOv1Oy65JPU03khcSl+/Vp75EnHWcVLhc7ZO3TBMYsDSyNw/rEh1C2
         jz2w==
X-Gm-Message-State: AOAM532SMruLFnSL6zmwRsS04s992UnPoXiETTc94M6hLpF6MaGjn44A
	5WWZqKqSsbiwHSLanuodZO8=
X-Google-Smtp-Source: ABdhPJxe8hw39aZZFXpnev0unp27wjmDVMsHLtbNQPlVQc3G7+M0KoOtmWmJJA7NbDh1xUf5cKWjaA==
X-Received: by 2002:a05:6512:11c3:: with SMTP id h3mr11665453lfr.366.1615915852525;
        Tue, 16 Mar 2021 10:30:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:6d4:: with SMTP id u20ls4676678lff.1.gmail; Tue, 16
 Mar 2021 10:30:51 -0700 (PDT)
X-Received: by 2002:a05:6512:207:: with SMTP id a7mr11717807lfo.393.1615915851301;
        Tue, 16 Mar 2021 10:30:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615915851; cv=none;
        d=google.com; s=arc-20160816;
        b=jjCfQ1bsNMnPNIjizPR8VSSd2sOeerLPo5tZ9UMHJcEJ3ukFUJbNT590kI8G4zY16F
         dFW/wW07FG0uXtmBqG11YjVmX04eSy5dJlShXfs2q7ZYVrF6sllirEmWKGiH6I4baU3a
         vDAScP4bszabSTxyUlVlEeGo80FuFbT2vzxQy+qQzVs/8iI3vYGPuW6MAmUMxK+s2o4J
         /lAdF29XVgNj6IQ2hGYQH2ac7ystOKHEKLPzlvKVmyeBcYWw2s94nDVJTgG9T5VqvFFa
         sEpx+h343KrCSWT8H7K0efqPOXRLJrvXQnPj2C9Jvi6rl73hIyNFUQbCsFTE0+Gpx9To
         f3Ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ure8kWkdZ5geLP/9Lu+/xSmpVEu0DA6buPVci38aSj0=;
        b=o8UwRYc8Horo5QQC7Samhh0/sdBjR70LUEH0Wz+zYPVnaTj1qSsJnsj7ocqSjQjWaP
         1gp9XjcuDPtHO0rdgIzT5kBUdAdqV5NY4AhahZv/ngF38u94CP8lom2vsR7EnD2TxZxm
         66GKAj/JkVq8yL0QJVSfCuz2I5DWmgpGi7GP3Axo2/HCZvFm1eABYmWPep+KGEGqnY/D
         9s/r+tzdqYCzI77weOmZVTTFxTI0CONmSUiTx93b6d73hi/U3gbo+U/y2dKcEMp6eZpz
         7nXRXd7eErpnkES571GGDkPsu0zCXR90M3iIEv0qrp2SK0U89V42NtUMberMNb0Tjwbr
         psQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Z678/QuL";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id i30si748321lfj.6.2021.03.16.10.30.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Mar 2021 10:30:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id y124-20020a1c32820000b029010c93864955so1912850wmy.5
        for <kasan-dev@googlegroups.com>; Tue, 16 Mar 2021 10:30:51 -0700 (PDT)
X-Received: by 2002:a05:600c:1548:: with SMTP id f8mr135921wmg.81.1615915850632;
        Tue, 16 Mar 2021 10:30:50 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:1d09:9676:5eaa:550])
        by smtp.gmail.com with ESMTPSA id b65sm101820wmh.4.2021.03.16.10.30.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Mar 2021 10:30:49 -0700 (PDT)
Date: Tue, 16 Mar 2021 18:30:00 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Luis Henriques <lhenriques@suse.de>
Cc: Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: Issue with kfence and kmemleak
Message-ID: <YFDrGL45JxFHyajD@elver.google.com>
References: <YFDf6iKH1p/jGnM0@suse.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFDf6iKH1p/jGnM0@suse.de>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Z678/QuL";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as
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

On Tue, Mar 16, 2021 at 04:42PM +0000, Luis Henriques wrote:
> Hi!
> 
> This is probably a known issue, but just in case: looks like it's not
> possible to use kmemleak when kfence is enabled:

Thanks for spotting this.

> [    0.272136] kmemleak: Cannot insert 0xffff888236e02f00 into the object search tree (overlaps existing)
> [    0.272136] CPU: 0 PID: 8 Comm: kthreadd Not tainted 5.12.0-rc3+ #92
> [    0.272136] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.14.0-0-g155821a-rebuilt.opensuse.org 04/01/2014
> [    0.272136] Call Trace:
> [    0.272136]  dump_stack+0x6d/0x89
> [    0.272136]  create_object.isra.0.cold+0x40/0x62
> [    0.272136]  ? process_one_work+0x5a0/0x5a0
> [    0.272136]  ? process_one_work+0x5a0/0x5a0
> [    0.272136]  kmem_cache_alloc_trace+0x110/0x2f0
> [    0.272136]  ? process_one_work+0x5a0/0x5a0
> [    0.272136]  kthread+0x3f/0x150
> [    0.272136]  ? lockdep_hardirqs_on_prepare+0xd4/0x170
> [    0.272136]  ? __kthread_bind_mask+0x60/0x60
> [    0.272136]  ret_from_fork+0x22/0x30
> [    0.272136] kmemleak: Kernel memory leak detector disabled
> [    0.272136] kmemleak: Object 0xffff888236e00000 (size 2097152):
> [    0.272136] kmemleak:   comm "swapper", pid 0, jiffies 4294892296
> [    0.272136] kmemleak:   min_count = 0
> [    0.272136] kmemleak:   count = 0
> [    0.272136] kmemleak:   flags = 0x1
> [    0.272136] kmemleak:   checksum = 0
> [    0.272136] kmemleak:   backtrace:
> [    0.272136]      memblock_alloc_internal+0x6d/0xb0
> [    0.272136]      memblock_alloc_try_nid+0x6c/0x8a
> [    0.272136]      kfence_alloc_pool+0x26/0x3f
> [    0.272136]      start_kernel+0x242/0x548
> [    0.272136]      secondary_startup_64_no_verify+0xb0/0xbb
> 
> I've tried the hack below but it didn't really helped.  Obviously I don't
> really understand what's going on ;-)  But I think the reason for this
> patch not working as (I) expected is because kfence is initialised
> *before* kmemleak.
> 
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 3b8ec938470a..b4ffd7695268 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -631,6 +631,9 @@ void __init kfence_alloc_pool(void)
>  
>  	if (!__kfence_pool)
>  		pr_err("failed to allocate pool\n");
> +	kmemleak_no_scan(__kfence_pool);
>  }

Can you try the below patch?

Thanks,
-- Marco

------ >8 ------

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index f7106f28443d..5891019721f6 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -12,6 +12,7 @@
 #include <linux/debugfs.h>
 #include <linux/kcsan-checks.h>
 #include <linux/kfence.h>
+#include <linux/kmemleak.h>
 #include <linux/list.h>
 #include <linux/lockdep.h>
 #include <linux/memblock.h>
@@ -481,6 +482,13 @@ static bool __init kfence_init_pool(void)
 		addr += 2 * PAGE_SIZE;
 	}
 
+	/*
+	 * The pool is live and will never be deallocated from this point on;
+	 * tell kmemleak this is now free memory, so that later allocations can
+	 * correctly be tracked.
+	 */
+	kmemleak_free_part_phys(__pa(__kfence_pool), KFENCE_POOL_SIZE);
+
 	return true;
 
 err:

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFDrGL45JxFHyajD%40elver.google.com.
