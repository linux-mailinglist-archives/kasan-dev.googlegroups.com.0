Return-Path: <kasan-dev+bncBDGIV3UHVAGBBWP42WKQMGQE2V7KCFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9977C5595FC
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jun 2022 11:05:30 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id d8-20020a05651c088800b0025a755647basf188567ljq.12
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jun 2022 02:05:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656061530; cv=pass;
        d=google.com; s=arc-20160816;
        b=WrBPRRSLabI1NRL/Ij00BEme6zOgrOknyAkv5bQmtNpG/rXGEScKTZBrjAHOKIfl8/
         JZGZGe16q+AWdw/fhSv/IK/1oD9C+tTHiuIf09qmoMBTcOguJsxeJYraHWfdjdjc8jYI
         RB5U8AAoCv+ElpybMW1lmUTH5spX1ThI9+v8k5LTlBuKhRjFOL9aJNSiHNhmXBbXKJxI
         AwyYzXp+Cu0xbRdKldo0Qy/lX6r+lkhTYfGDkr2mQ5P9NFHqw4mFEk2M4qLwiKdQK6u/
         cnEz+Kh6gw8AqFLOiTrlK5LSi+3FXVN95+JiWVC0Atv65YLVYfkQxhdq2cjK4KE2A5+Q
         E7Bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wQcdkIWrWRNsKUln8PMKrAe41H0hxhRbxZkLx3XaekE=;
        b=034jcvPFssutsp8Uuqm0dh3Ye/ncwsbkcYGGUneqA0opWu7uyy7hqJSfF0tfpGbv3V
         XoHVyeYIzHLJ3eBas79IHBoL5/AOsJvDhkrtf5eR76j83ZPbtrRfi3KQkItDdkYILDSZ
         9jSL8EXHgqSjOVA1U7h2hM95JF1rR6v5b0MqOsWaO5bqmm5iRaEcv8A6d3K2cMcQr/QN
         OoEVXsdES88X4+iXBfdf1gx2J8uSOTzRqUByYZFGEQpTlHfVaGG9cMLd6RWMDPGinoj0
         b8SxYeW1qSfmwM0l6I+aVm9yjzftyAmbqUesSQtIoTCJhT+wJHVtX86VPPsDii5f7lgj
         WhWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=GzGLhCTG;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=UqKN7qtz;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wQcdkIWrWRNsKUln8PMKrAe41H0hxhRbxZkLx3XaekE=;
        b=ZbdL2KeJ6BlOInd87bHO4Daf1YeiPMO8DLOLa0EZhSD1b4OK6v0+jenOhPfyqSnNHk
         Oeij93aNM6I9tvrU34Kr7+LXBM2ARFjnhYtRSRFK/FZP1L1QWWz1dIgfcrcPtC/fYXMT
         Dxd4HNtAdtMIA81cfQL9qqpijKwa592a/a0vlT6pbBWrj/JB8zW5uR/6XoXnyPMRbfJs
         EuCAoqSDJ1Y5X3Mw0maIm/2zmbg0u4djt8iy5qRLwDn2rpNiEY2F27p+NbLtoT3NzBMy
         oT3NXxxNrl+GC25UEvFAKxnMpK3Nw9Y5uc9iWk5gHxZecwuae5YGZPApmHl1Uend48ub
         dDYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wQcdkIWrWRNsKUln8PMKrAe41H0hxhRbxZkLx3XaekE=;
        b=iHet0J0Dl4N0AZBe0NE6K24DlFR9NOOeLjKgFSAaGzAihh7EfxzWBMbo9u+CUW2TZP
         6mMGmgFlDZ/B8iPSZq/7bvlRS8YvnycbIqBSRE9DDpeyFSaEIzamLbvqU24WvOdzD5Bo
         Uz7MxX0xNW+lE5JaZsFmz+OYqLOL6GuPeRI/Tbw8qdxjR2JQOyJEDxvmNEsEHsSBK4wz
         AzIzY67iz4gwOJGOavCZ6XF8rfmn4dMOxLd8nbBlhxiSTaPpZNZc94n5BUyXipYbzGRl
         LOXqyXhoAvTgvNkbUXWfZs490YFCdUjEdOwQeZ2Jwf/nsICOEbgrsensdNt2Je7ha2gz
         wQxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+f7ASGPZk/BxgqEktlGSZE/TZQBPvtl8wUFaddCQEkysgenvVc
	qwP9fYfknUt6llLItVy7C+E=
X-Google-Smtp-Source: AGRyM1uZgC9xlpTi6UsdpOsOdjAYG8aPzfB3PaIydnyP4yxXX0Z91z1JNrD/zCrzsuM6CMtliWziww==
X-Received: by 2002:a2e:a36b:0:b0:25a:8457:e3f9 with SMTP id i11-20020a2ea36b000000b0025a8457e3f9mr7002586ljn.506.1656061529755;
        Fri, 24 Jun 2022 02:05:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als25011lfa.2.gmail; Fri, 24 Jun 2022
 02:05:28 -0700 (PDT)
X-Received: by 2002:ac2:5922:0:b0:47f:a067:c83a with SMTP id v2-20020ac25922000000b0047fa067c83amr5664167lfi.268.1656061528628;
        Fri, 24 Jun 2022 02:05:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656061528; cv=none;
        d=google.com; s=arc-20160816;
        b=alFbRtLFjWf9YLZzMsyxij37ezVRhCiVrTvUmB3ZcJfdT6lUmXt28MiYk8nkXQuLcQ
         r/gJN5yocEXNe6iXUw1x/JZ2aUFV5aSi3OoBvYICYXXgv1AjYFHwdAkxVOHj97OgpHub
         oz0kq7j8xFaIse5N11/F9cTd+sEV+I2mIUE5vbLPeBhyRcYn4W65lKJb6Zri1zanVD0Y
         BehVyqAfC9En9g4F6vumpcotbJ3uARo5K8eIH8xiN0zhZ8qaByn1zopVVQr0cA8fJ+Uv
         lVofxrh07q5xMatCrD6qfYarZ8UdwELBcfIvRQGTy3Pbr2jKIccej9OLURRHHPyg2WRk
         4nmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=MfsUGiGWHTVWBDtum+AXLC4uLJ41OMe5+nGtjZmhQb4=;
        b=tzMByRNgbyNmHCktM1mXiE6mf1ruY8n8DYiSHwnN8l5jMQYqICJkwe9K+8Y0U10EKq
         SlMdcq2ssj76D1mDivx+sG5thv3rUfYLYjNnFJe9BURSNZIymr66ldq9IQsr8cInlL1g
         KlhlmeANLLRu/5o/HUxwnNFalWJtFyM5RlU+hJj8JGZVKSIASqo5b8ECiEaT1cFm4PnC
         eQHlAOhyQkSUFiY9nsCLM3Qy52myUdkk+EX/2ml+B9tsFPfqc1FjrcZWH/fishqab32q
         Un//vD0lPVyiSSUqJbnafs7W4YmuUpsFHyERfFiHAExRHH3YoSv0sbqduC+UcdIBpDTs
         Mg8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=GzGLhCTG;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=UqKN7qtz;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id c5-20020a056512238500b0047f655fc94csi77356lfv.11.2022.06.24.02.05.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Jun 2022 02:05:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Fri, 24 Jun 2022 11:05:26 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Mike Galbraith <efault@gmx.de>
Cc: RT <linux-rt-users@vger.kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Subject: Re: v5.19-rc2-rt3: mm/kfence might_sleep() splat
Message-ID: <YrV+Vu47VDGDQpx8@linutronix.de>
References: <bf74019da22b3c6a750153cbc74ffe3fcdb0ddf7.camel@gmx.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bf74019da22b3c6a750153cbc74ffe3fcdb0ddf7.camel@gmx.de>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=GzGLhCTG;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=UqKN7qtz;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates
 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On 2022-06-18 11:34:51 [+0200], Mike Galbraith wrote:
> I moved the prandom_u32_max() call in kfence_guarded_alloc() out from
> under raw spinlock to shut this one up.

Care to send a patch? I don't even why kfence_metadata::lock is a
raw_spinlock_t. This is the case since the beginning of the code.

> [    1.128544] BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:46
> [    1.128546] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 90, name: kworker/u16:3
> [    1.128547] preempt_count: 1, expected: 0
> [    1.128548] RCU nest depth: 1, expected: 1
> [    1.128549] CPU: 3 PID: 90 Comm: kworker/u16:3 Tainted: G        W         5.19.0.g0639b59-master-rt #2 55e5fbd63d8381661776ddec390c2b764f305c0b
> [    1.128551] Hardware name: MEDION MS-7848/MS-7848, BIOS M7848W08.20C 09/23/2013
> [    1.128552] Workqueue: events_unbound async_run_entry_fn
> [    1.128556] Call Trace:
> [    1.128557]  <TASK>
> [    1.128558]  dump_stack_lvl+0x44/0x58
> [    1.128562]  __might_resched+0x141/0x160
> [    1.128566]  rt_spin_lock+0x2d/0x70
> [    1.128569]  get_random_u32+0x45/0x100
> [    1.128575]  __kfence_alloc+0x3f4/0x6c0
> [    1.128647]  kmem_cache_alloc_lru+0x1d8/0x220
> [    1.128649]  xas_alloc+0x9b/0xc0
> [    1.128651]  xas_create+0x20c/0x390
> [    1.128653]  xas_store+0x52/0x5a0
> [    1.128655]  __filemap_add_folio+0x189/0x5a0
> [    1.128660]  filemap_add_folio+0x38/0xa0
> [    1.128661]  __filemap_get_folio+0x1b0/0x580
> [    1.128665]  pagecache_get_page+0x13/0x80
> [    1.128667]  simple_write_begin+0x20/0x2d0
> [    1.128669]  generic_perform_write+0xae/0x1e0
> [    1.128671]  __generic_file_write_iter+0x141/0x180
> [    1.128672]  generic_file_write_iter+0x5d/0xb0
> [    1.128674]  __kernel_write+0x139/0x2f0
> [    1.128676]  kernel_write+0x56/0x1a0
> [    1.128678]  xwrite.constprop.8+0x35/0x8e
> [    1.128682]  do_copy+0xee/0x13a
> [    1.128685]  write_buffer+0x27/0x37
> [    1.128687]  flush_buffer+0x34/0x8b
> [    1.128690]  unxz+0x1b8/0x301
> [    1.128695]  unpack_to_rootfs+0x17f/0x2ae
> [    1.128698]  do_populate_rootfs+0x59/0x108
> [    1.128700]  async_run_entry_fn+0x2b/0x110
> [    1.128701]  process_one_work+0x21f/0x4a0
> [    1.128703]  worker_thread+0x39/0x3d0
> [    1.128706]  kthread+0x13e/0x160
> [    1.128709]  ret_from_fork+0x1f/0x30
> [    1.128711]  </TASK>

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YrV%2BVu47VDGDQpx8%40linutronix.de.
