Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBXODT6LQMGQEIRCHK7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id EB412586CBD
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Aug 2022 16:23:25 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id d27-20020adfa41b000000b0021ee714785fsf2637563wra.18
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Aug 2022 07:23:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659363805; cv=pass;
        d=google.com; s=arc-20160816;
        b=x6z0SJsz89kUNzl6IQVS1fSuNNK5KMSOhG8kzbUVqlVBOwLFFjeYo1u2w9MEsCeQyN
         D2HCyHyGap2//zH1odoq0ARR0J+thJDBmUO45ipKshaKEo88zx0ffk/hfZckGZ7Bjpn1
         gP4U4LMcBGJfK8+Ch1VEcENGAW6hJrt11LS6cDW261uNAPhjfZ8Dbmqew+Id9w8WcyCi
         6+/mhGjG7gjNgJorzNKAujhyl0p9MoQOy3GhYUQdsUekXZlKhx59zLrsPtHHXeZiIwrq
         De+stLxFn/iOTiNCH3rqwE8R9MO3TFZAP+aqJG2Eea5J5yKYxoVCoQd30WdDXViGsKfh
         sEOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=66hfc0vXIAHOfdyy3hyXVRMaDvMYXngLcY9farZr1zY=;
        b=njZkLTLO3nXQsNXRzq3nUvdi6ZFRh+dBjNpcFOgDDxTNiq7opZhHKAxlepCX8xB2iF
         eoq+d7uDs/dL1akLePA0TQ+pnMLwrDgbKRlvvR+dhXo6yfd8R8umyAE6r6adFTc80JXF
         TMkfkCgkXEgjwO3lGicakydeYeQQnHdEVUnwgoKsIl29cSyLETKqhRtO8rl6LdKD/k4h
         Q7UACK0YSDEu64n1QvQ+/+PfrjPwZ6XWG0siZkFzDLiym7DkeB2W069/GXDCp45RBgfb
         oluSDTjcdH9UYR59DTL47yPwfn0sRnEDcn8ZiJnoCwin84oTKh9lt3XTEhR7oSyiuNkd
         seMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=w2sNXink;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=mv9t6AFJ;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=66hfc0vXIAHOfdyy3hyXVRMaDvMYXngLcY9farZr1zY=;
        b=NLb7B177vmOMNuW0fxSkjG57ubIlOjsq7xK69ayz1Hg0ewijLUNrW36L91T3WwO1zd
         nfByxen9LX9QtqDn2LKu0vlc8WCMzWb+YJBvSQcG3d5uqKevoJXOa5KCx+JXUmvQsus5
         HXFqhMIgLLM6VKuCzgqLM/55c7o8vv0PXKodGsauZ/HMZjVRd/R3iC+FCcAciA+EPgex
         dTPb/ZdXbJKxnwqz3ck4afzVhkQ0U1W6Wfqh5vntZ6AN8YHOLzeU5ylqp6M88j/q+8Y8
         dUo8RAzNsoOsbmJk/vC1PaBp3xubHR6Jo81f8u+74kbgjBuxcgApnq3btpK3uuqyYRtU
         ONXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=66hfc0vXIAHOfdyy3hyXVRMaDvMYXngLcY9farZr1zY=;
        b=r0hh/NELKPy+wYvwkdg61d7IJj76PGObfVu1Mnm7sHsiXgx20S69DGN3pkEUMfq2xJ
         WYLxUShinZ9Hh6qq0dl/vdGD9t/OiAOlK4VPjG0rotzRHxMTGLygODTTUZtKlQCpsGuB
         BGKLGmfT48hWOx6is9a+EOHX1wP2jsLEhtku7SpgfSXNG7JYRwCX34lkIJNR3sEpUH2d
         AbeeKNESoSbyImO/lkw3zMpRZwz/6BOJhzsZ4kOy02yHagLYImCTNQFdxqjdiUQgyV+k
         BQOJJ9+ofuXG36DBAd5lDowu8UJSq2D5FMf3wsY5r3I0ki3+r1EGehDPwzkE76ATKAEt
         FMuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+CHOwi4MoWWrZgDGaa+zCuqFIbnakdDaoB5e3ad9+eYV9yMof1
	MtEOjS1NnuSlweF7qLK3Bzk=
X-Google-Smtp-Source: AGRyM1uoLJXJsAD58ZXPAv1uXAGwGwQ+6Et0ynwFa0RFPTjzxyTYAtmUIjjin/Eu/kg/SJgp5H5D/Q==
X-Received: by 2002:a05:600c:1001:b0:3a3:a221:78ab with SMTP id c1-20020a05600c100100b003a3a22178abmr11432206wmc.164.1659363805505;
        Mon, 01 Aug 2022 07:23:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:668c:0:b0:21f:15aa:1c69 with SMTP id l12-20020a5d668c000000b0021f15aa1c69ls11069616wru.0.-pod-prod-gmail;
 Mon, 01 Aug 2022 07:23:24 -0700 (PDT)
X-Received: by 2002:a5d:4202:0:b0:21f:10f9:a968 with SMTP id n2-20020a5d4202000000b0021f10f9a968mr9549237wrq.231.1659363804105;
        Mon, 01 Aug 2022 07:23:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659363804; cv=none;
        d=google.com; s=arc-20160816;
        b=CwYHPajhBfK/UWziypzlmPeNTMiZDD86LF9+TFqgkhFCsbFOEnqKimhtvCxL8tSwSx
         0h+srRnG4n/+XuUb7OTJhuqYQEgacyhCx6McAT9GyaHm17lHB46uSt5B3TxfDc0U2mk9
         otnEvsrntiE0ZCrNNeOW0y/R5oMWRUs0TNJBg8CrrwyHMaWE1XvBDZ+QxOhx47luSy18
         kFUCa2JOkxSwZlbZ1zwmWF60qIPOkPcn6QmTFDKbP+CYGDD6tVdF5RcUr9BIcU6CurX3
         N9xvzvwYCoAprQgLareFnmPzHo2hjabvz2Dwgw7J8btyyLsLPFLepdcnMVVrWf4c0qik
         gj1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=YuzfHQ5gcHDxVmgktoZtWnqMi1COmyK3WWW+iFcUeNc=;
        b=d+66BcwMeyhmbQnXBLjfIr7EY9sUEoeNE4dFx29XEPWM0Goj7IaeZEFbsl3nKVPQNW
         2pSh55FQJEeLp0PPeyOZ5UcrjkPmMUQhN6Muk/urgqnGNOhlS3wIO3F4AyNy6vSiE/DO
         S/t2NYVQ0F4gB2mtXjr7LUzH5tFLzFXiguGkosu4WwbJe+McXEOMT74ux1yFbhvggwNs
         DOV0QyuEV8cnGuXPxWX1IywXxVWBmENlgS0Xy382cRGtvAM6naZgXdD4l1gYI+4TMhTs
         J0oGlwujNs1wZPJ4LBg5Kmv+t3KVi5DxHWmbQTfVamYR2m4ekDM4qM690eR/BMIuCth5
         1qwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=w2sNXink;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=mv9t6AFJ;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id bu25-20020a056000079900b0022068e0dba1si57767wrb.4.2022.08.01.07.23.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Aug 2022 07:23:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id B44D52088B;
	Mon,  1 Aug 2022 14:23:23 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 688AC13AAE;
	Mon,  1 Aug 2022 14:23:23 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id bQfJGNvh52JrVgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 01 Aug 2022 14:23:23 +0000
Message-ID: <0e545088-d140-4c84-bbb2-a3be669740b2@suse.cz>
Date: Mon, 1 Aug 2022 16:23:23 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.11.0
Subject: Re: [mm/slub] 3616799128:
 BUG_kmalloc-#(Not_tainted):kmalloc_Redzone_overwritten
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>, "Sang, Oliver" <oliver.sang@intel.com>
Cc: lkp <lkp@intel.com>, LKML <linux-kernel@vger.kernel.org>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "lkp@lists.01.org" <lkp@lists.01.org>,
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Hansen, Dave" <dave.hansen@intel.com>,
 Robin Murphy <robin.murphy@arm.com>, John Garry <john.garry@huawei.com>,
 Kefeng Wang <wangkefeng.wang@huawei.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com
References: <20220727071042.8796-4-feng.tang@intel.com>
 <YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020> <YuY6Wc39DbL3YmGi@feng-skl>
 <Yudw5ge/lJ26Hksk@feng-skl>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <Yudw5ge/lJ26Hksk@feng-skl>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=w2sNXink;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=mv9t6AFJ;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 8/1/22 08:21, Feng Tang wrote:
> On Sun, Jul 31, 2022 at 04:16:53PM +0800, Tang, Feng wrote:
>> Hi Oliver,
>> 
>> On Sun, Jul 31, 2022 at 02:53:17PM +0800, Sang, Oliver wrote:
>> > 
>> > 
>> > Greeting,
>> > 
>> > FYI, we noticed the following commit (built with gcc-11):
>> > 
>> > commit: 3616799128612e04ed919579e2c7b0dccf6bcb00 ("[PATCH v3 3/3] mm/slub: extend redzone check to cover extra allocated kmalloc space than requested")
>> > url: https://github.com/intel-lab-lkp/linux/commits/Feng-Tang/mm-slub-some-debug-enhancements/20220727-151318
>> > base: git://git.kernel.org/cgit/linux/kernel/git/vbabka/slab.git for-next
>> > patch link: https://lore.kernel.org/linux-mm/20220727071042.8796-4-feng.tang@intel.com
>> > 
>> > in testcase: boot
>> > 
>> > on test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
>> > 
>> > caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
>> > 
>> > 
>> > If you fix the issue, kindly add following tag
>> > Reported-by: kernel test robot <oliver.sang@intel.com>
>> > 
>> > 
>> > [   50.637839][  T154] =============================================================================
>> > [   50.639937][  T154] BUG kmalloc-16 (Not tainted): kmalloc Redzone overwritten
>> > [   50.641291][  T154] -----------------------------------------------------------------------------
>> > [   50.641291][  T154]
>> > [   50.643617][  T154] 0xffff88810018464c-0xffff88810018464f @offset=1612. First byte 0x7 instead of 0xcc
>> > [   50.645311][  T154] Allocated in __sdt_alloc+0x258/0x457 age=14287 cpu=0 pid=1
>> > [   50.646584][  T154]  ___slab_alloc+0x52b/0x5b6
>> > [   50.647411][  T154]  __slab_alloc+0x1a/0x22
>> > [   50.648374][  T154]  __kmalloc_node+0x10c/0x1e1
>> > [   50.649237][  T154]  __sdt_alloc+0x258/0x457
>> > [   50.650060][  T154]  build_sched_domains+0xae/0x10e8
>> > [   50.650981][  T154]  sched_init_smp+0x30/0xa5
>> > [   50.651805][  T154]  kernel_init_freeable+0x1c6/0x23b
>> > [   50.652767][  T154]  kernel_init+0x14/0x127
>> > [   50.653594][  T154]  ret_from_fork+0x1f/0x30
>> > [   50.654414][  T154] Slab 0xffffea0004006100 objects=28 used=28 fp=0x0000000000000000 flags=0x1fffc0000000201(locked|slab|node=0|zone=1|lastcpupid=0x3fff)
>> > [   50.656866][  T154] Object 0xffff888100184640 @offset=1600 fp=0xffff888100184520
>> > [   50.656866][  T154]
>> > [   50.658410][  T154] Redzone  ffff888100184630: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  ................
>> > [   50.660047][  T154] Object   ffff888100184640: 00 32 80 00 81 88 ff ff 01 00 00 00 07 00 80 8a  .2..............
>> > [   50.661837][  T154] Redzone  ffff888100184650: cc cc cc cc cc cc cc cc                          ........
>> > [   50.663454][  T154] Padding  ffff8881001846b4: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a              ZZZZZZZZZZZZ
>> > [   50.665225][  T154] CPU: 0 PID: 154 Comm: systemd-udevd Not tainted 5.19.0-rc5-00010-g361679912861 #1
>> > [   50.666861][  T154] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian-1.16.0-4 04/01/2014
>> > [   50.668694][  T154] Call Trace:
>> > [   50.669331][  T154]  <TASK>
>> > [   50.669832][  T154]  dump_stack_lvl+0x57/0x7d
>> > [   50.670601][  T154]  check_bytes_and_report+0xca/0xfe
>> > [   50.671436][  T154]  check_object+0xdc/0x24d
>> > [   50.672163][  T154]  free_debug_processing+0x98/0x210
>> > [   50.673904][  T154]  __slab_free+0x46/0x198
>> > [   50.675746][  T154]  qlist_free_all+0xae/0xde
>> > [   50.676552][  T154]  kasan_quarantine_reduce+0x10d/0x145
>> > [   50.677507][  T154]  __kasan_slab_alloc+0x1c/0x5a
>> > [   50.678327][  T154]  slab_post_alloc_hook+0x5a/0xa2
>> > [   50.680069][  T154]  kmem_cache_alloc+0x102/0x135
>> > [   50.680938][  T154]  getname_flags+0x4b/0x314
>> > [   50.681781][  T154]  do_sys_openat2+0x7a/0x15c
>> > [   50.706848][  T154] Disabling lock debugging due to kernel taint
>> > [   50.707913][  T154] FIX kmalloc-16: Restoring kmalloc Redzone 0xffff88810018464c-0xffff88810018464f=0xcc
>> 
>> Thanks for the report!
>> 
>> From the log it happened when kasan is enabled, and my first guess is
>> the data processing from kmalloc redzone handling had some conflict
>> with kasan's in allocation path (though I tested some kernel config
>> with KASAN enabled)
>> 
>> Will study more about kasan and reproduce/debug this. thanks
> 
> Cc kansan  mail list.
> 
> This is really related with KASAN debug, that in free path, some
> kmalloc redzone ([orig_size+1, object_size]) area is written by
> kasan to save free meta info.
> 
> The callstack is:
> 
>   kfree
>     slab_free
>       slab_free_freelist_hook
>           slab_free_hook
>             __kasan_slab_free
>               ____kasan_slab_free
>                 kasan_set_free_info
>                   kasan_set_track    
> 
> And this issue only happens with "kmalloc-16" slab. Kasan has 2
> tracks: alloc_track and free_track, for x86_64 test platform, most
> of the slabs will reserve space for alloc_track, and reuse the
> 'object' area for free_track.  The kasan free_track is 16 bytes
> large, that it will occupy the whole 'kmalloc-16's object area,
> so when kmalloc-redzone is enabled by this patch, the 'overwritten'
> error is triggered.
> 
> But it won't hurt other kmalloc slabs, as kasan's free meta won't
> conflict with kmalloc-redzone which stay in the latter part of
> kmalloc area.
> 
> So the solution I can think of is:
> * skip the kmalloc-redzone for kmalloc-16 only, or
> * skip kmalloc-redzone if kasan is enabled, or
> * let kasan reserve the free meta (16 bytes) outside of object
>   just like for alloc meta

Maybe we could add some hack that if both kasan and SLAB_STORE_USER is
enabled, we bump the stored orig_size from <16 to 16? Similar to what
__ksize() does.

> I don't have way to test kasan's SW/HW tag configuration, which
> is only enabled on arm64 now. And I don't know if there will
> also be some conflict.
> 
> Thanks,
> Feng
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0e545088-d140-4c84-bbb2-a3be669740b2%40suse.cz.
