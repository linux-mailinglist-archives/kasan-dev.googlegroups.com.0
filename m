Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6N7QSJQMGQEHIWIHAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id C9C79509BDB
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 11:12:25 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id dn26-20020a05640222fa00b0041d85c7a190sf2848278edb.22
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 02:12:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650532345; cv=pass;
        d=google.com; s=arc-20160816;
        b=qFWAFFLKCGok7NYEwzt36anzSOFwV6QVAgoVGgxwZOLkrTXNPoBWgoTvK9d2usNAOe
         1ebcFML2YouTZb2fVkfPkafEjoqgzAhFetVFLx79LLBC5a2n/JuUGTuhd1ZOypFYHLWE
         4I+IqfzTbuAowClBrTsYfjQQIC4AFMwXaljygIHHsBLxSMr29Pb4q2TkGWFpp1Uz8NRm
         szTWou3Mh9z4r1aLaHtSIIyrm5V14EZpMZc2x4+b8uzpA9j0VhhL4GqPdfGL4XAugnzk
         iSuUp5ZYqmMMre+yYjY5I96LOdcSKkxDWBWokiHj87EKs8qXd/fqz4IoV63lLW/ZlokB
         aHoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=jrA0BVTdvg84S/gzTCPq42vkdAPhlJasPMqU4OP/nQc=;
        b=JuWhu++3H71YN2/lD7ayyfSbDX8mCCbSJGImOd+/fTO/2lgKJpEy8AA+20oqCTZWJ3
         nqLpXvxHZK7Y7i1P2fIEYgLKT+LEzB40KiSH2+qvU9BKnrbawXZr+fKfPxju357hnqsj
         GeRvGoorWPR2NjCLS7yanvbgY9xxYG7Jz5oPzialfSBjzivao8UdWJ9TGltF4pK6tzaH
         pjRcAtitb6Y+z5DPW5lWCH0vprOyjKXQDea4zzKitCgclutcnD0xUc/8Hm6HEpCrHzHH
         lyMjvFdkzPkloSydvPZ4FKNiE3SSINLN1GikuyMpYz/02btH5D+s2sU2zyQo3DTayyOF
         WpUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HmW83Qhk;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=jrA0BVTdvg84S/gzTCPq42vkdAPhlJasPMqU4OP/nQc=;
        b=fhBjSGznjUgGpfiFsOH5RXRnxabaHcAh9xvVeiZ0Tfl+4rMIWCYUKuBWv42CSMZNfL
         +KxVvjFWFxpnwO27Ns689cXiQ5Yxysrck1DWYb6lZejUJdNzQXv1f3/iiSEYia+egpNj
         brxw56j0hladSJDP8GF9PJDhRcrn59nob9RYN5yXzP2iWkf0yzT3hQtigEvdomKjXCoc
         Z67Vfv5Qd7/Sv9K5+DIXaokGJrtG4SjSLTvamIdgoOUSupFcTdim5t4dZMJBOYv9qsRw
         rrQwwRmSkUSM4EaVGLTIHLx3e68SzNmuT5oX02uH4IAjaamU1TtRSDV9q1vu2p9Of2W1
         UezQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jrA0BVTdvg84S/gzTCPq42vkdAPhlJasPMqU4OP/nQc=;
        b=qNK0ur93VIe6IFYRPMfFYZDhbrbH32cpxX6VGRu3V0DGrW/rpCt4FWBg85Fu2ZU11V
         Foo8K7X0Mmc7CgK4EdyV/C4ixohkbAg04yoZjDNHxUUQnItpKvISW8w5XifwtMetU3tO
         B8AvxmIVjwzRp8zksWwf/Uc0Q8VHH2roD+476Ij6uv0HwlIOUpqvNi/ySj0jn2pxUj2F
         yIPBF+XYOxTgxwzs29oXhIHkx/6YLepNUj8VshO7KFfmA33ka2jMbML/Eg0z+lXVCry2
         C+AUk5MhEgxBCvgVUJf6gm00plMm9k8Gi1aQ+n7cXRLsKHHv21FoqOFgjZ14cAjSrhoh
         IuPQ==
X-Gm-Message-State: AOAM531zdGpqSYvHQNb1WYd+P9qQdrEhkArQnocfHjET7j3EXD3Xm87h
	pPZjdTXflllBBQd+j+8X7IQ=
X-Google-Smtp-Source: ABdhPJwaHDroiU8zcxXzst7YhyBUEvmY/hYUXHjYdwAHoVezgK93Aom9su8Zxu2vmEJnxZtjSxZHaQ==
X-Received: by 2002:a17:907:60d0:b0:6e0:93af:1b5e with SMTP id hv16-20020a17090760d000b006e093af1b5emr21993546ejc.653.1650532345483;
        Thu, 21 Apr 2022 02:12:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:478d:b0:6e8:95ff:b734 with SMTP id
 cw13-20020a170906478d00b006e895ffb734ls2521998ejc.5.gmail; Thu, 21 Apr 2022
 02:12:24 -0700 (PDT)
X-Received: by 2002:a17:907:2d21:b0:6f0:7dd:7490 with SMTP id gs33-20020a1709072d2100b006f007dd7490mr5687712ejc.702.1650532344204;
        Thu, 21 Apr 2022 02:12:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650532344; cv=none;
        d=google.com; s=arc-20160816;
        b=CasKRm7o2r7FlBLKtt94Ta5By2s7IWAcwFeqbPWJ21xiI5RXUmuDGvz86GsWLg8Ghm
         twCqZFcB8TGPVfeAkUa+kVl2++vFQ3Hr4qk6u1ee2h2oFl3IsQshqY0bTTmQeme2IjQs
         YMow/UPKXp/QHBX2wtD89s1uT+DcNgpH9FsrXyo3bWWLdqyM6zIQTiG7u8b0IfDkAsFv
         YwYFajJ8P8CwNWi/ONT/DKcDqeO+v2lqOzDcYLvzLjWRHKD3f4yjuCCDywHTsIzrCx8l
         zHUrRKd8BVmk27hrY8ALmmhPA9ozbmPH1BDyIMvUhUzJ255rrWpwoSbdcMrFA+h+NHvS
         Njmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=wrZJAQCvZMNBHOHFxhe/p/8wX8+3w7RNtn7JZy9xcqM=;
        b=qh8QUDEZq8CxpipndaCUEjJdVEWYEqYV0YPS1c+xkZLseHfPOtJ/xZf0YjmC+wkQvd
         Jib82z9e3nmegaSW5k4VbAysGukpOYjvQ6VpOhGrtRQX/BDuAnhrz40EEP+Lc7eJKtc8
         9Hbk2/HqEe77cqMW4oTnDgE38CU5SUnffNl+WbOiULipIs8t2nRV1q0mJiPsQh6846hc
         q9nxOxcWVaXeHTGHoSLyqjGzUl5gTgb2JEj0OVAxVKTolHy1lGVLBTB5sUgdshD0idYe
         Hx54G3be1UK2cfuL66BaxTMxoZ5dHOxB2h35X1niCblzxK8uRvbU+iuUpvA6RNK0C3AD
         QGTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HmW83Qhk;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id j1-20020a50d001000000b0041b5ea4060asi230928edf.5.2022.04.21.02.12.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Apr 2022 02:12:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id i20so5708387wrb.13
        for <kasan-dev@googlegroups.com>; Thu, 21 Apr 2022 02:12:24 -0700 (PDT)
X-Received: by 2002:a05:6000:1864:b0:20a:9ac6:b166 with SMTP id d4-20020a056000186400b0020a9ac6b166mr13332622wri.354.1650532343767;
        Thu, 21 Apr 2022 02:12:23 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:64a4:39d5:81cc:c8fd])
        by smtp.gmail.com with ESMTPSA id bi26-20020a05600c3d9a00b0038ed39dbf00sm1543151wmb.0.2022.04.21.02.12.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Apr 2022 02:12:22 -0700 (PDT)
Date: Thu, 21 Apr 2022 11:12:17 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: syzbot <syzbot+ffe71f1ff7f8061bcc98@syzkaller.appspotmail.com>,
	Muchun Song <songmuchun@bytedance.com>
Cc: akpm@linux-foundation.org, dvyukov@google.com, glider@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, syzkaller-bugs@googlegroups.com,
	Roman Gushchin <roman.gushchin@linux.dev>, cgroups@vger.kernel.org
Subject: Re: [syzbot] WARNING in __kfence_free
Message-ID: <YmEf8dpSXJeZ2813@elver.google.com>
References: <000000000000f46c6305dd264f30@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <000000000000f46c6305dd264f30@google.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HmW83Qhk;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::434 as
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

On Thu, Apr 21, 2022 at 01:58AM -0700, syzbot wrote:
> Hello,
> 
> syzbot found the following issue on:
> 
> HEAD commit:    559089e0a93d vmalloc: replace VM_NO_HUGE_VMAP with VM_ALLO..
> git tree:       upstream
> console output: https://syzkaller.appspot.com/x/log.txt?x=10853220f00000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=2e1f9b9947966f42
> dashboard link: https://syzkaller.appspot.com/bug?extid=ffe71f1ff7f8061bcc98
> compiler:       aarch64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2
> userspace arch: arm64
> 
> Unfortunately, I don't have any reproducer for this issue yet.
> 
> IMPORTANT: if you fix the issue, please add the following tag to the commit:
> Reported-by: syzbot+ffe71f1ff7f8061bcc98@syzkaller.appspotmail.com
> 
> ------------[ cut here ]------------
> WARNING: CPU: 0 PID: 2216 at mm/kfence/core.c:1022 __kfence_free+0x84/0xc0 mm/kfence/core.c:1022

That's this warning in __kfence_free:

	#ifdef CONFIG_MEMCG
		KFENCE_WARN_ON(meta->objcg);
	#endif

introduced in 8f0b36497303 ("mm: kfence: fix objcgs vector allocation").

Muchun, are there any circumstances where the assumption may be broken?
Or a new bug elsewhere?

> Modules linked in:
> CPU: 0 PID: 2216 Comm: syz-executor.0 Not tainted 5.18.0-rc3-syzkaller-00007-g559089e0a93d #0
> Hardware name: linux,dummy-virt (DT)
> pstate: 80400009 (Nzcv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
> pc : __kfence_free+0x84/0xc0 mm/kfence/core.c:1022
> lr : kfence_free include/linux/kfence.h:186 [inline]
> lr : __slab_free+0x2e4/0x4d4 mm/slub.c:3315
> sp : ffff80000a9fb980
> x29: ffff80000a9fb980 x28: ffff80000a280040 x27: f2ff000002c01c00
> x26: ffff00007b694040 x25: ffff00007b694000 x24: 0000000000000001
> x23: ffff00007b694000 x22: ffff00007b694000 x21: f2ff000002c01c00
> x20: ffff80000821accc x19: fffffc0001eda500 x18: 0000000000000002
> x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
> x14: 0000000000000001 x13: 000000000005eb7f x12: f7ff000007a08024
> x11: f7ff000007a08000 x10: 0000000000000000 x9 : 0000000000000014
> x8 : 0000000000000001 x7 : 0000000000094000 x6 : ffff80000a280000
> x5 : ffff80000821accc x4 : ffff80000a50e078 x3 : ffff80000a280348
> x2 : f0ff00001e325c00 x1 : ffff80000a522b40 x0 : ffff00007b694000
> Call trace:
>  __kfence_free+0x84/0xc0 mm/kfence/core.c:1022
>  kfence_free include/linux/kfence.h:186 [inline]
>  __slab_free+0x2e4/0x4d4 mm/slub.c:3315
>  do_slab_free mm/slub.c:3498 [inline]
>  slab_free mm/slub.c:3511 [inline]
>  kfree+0x320/0x37c mm/slub.c:4552
>  kvfree+0x3c/0x50 mm/util.c:615
>  xt_free_table_info+0x78/0x90 net/netfilter/x_tables.c:1212
>  __do_replace+0x240/0x330 net/ipv6/netfilter/ip6_tables.c:1104
>  do_replace net/ipv6/netfilter/ip6_tables.c:1157 [inline]
>  do_ip6t_set_ctl+0x374/0x4e0 net/ipv6/netfilter/ip6_tables.c:1639
>  nf_setsockopt+0x68/0x94 net/netfilter/nf_sockopt.c:101
>  ipv6_setsockopt+0xa8/0x220 net/ipv6/ipv6_sockglue.c:1026
>  tcp_setsockopt+0x38/0xdb4 net/ipv4/tcp.c:3696
>  sock_common_setsockopt+0x1c/0x30 net/core/sock.c:3505
>  __sys_setsockopt+0xa0/0x1c0 net/socket.c:2180
>  __do_sys_setsockopt net/socket.c:2191 [inline]
>  __se_sys_setsockopt net/socket.c:2188 [inline]
>  __arm64_sys_setsockopt+0x2c/0x40 net/socket.c:2188
>  __invoke_syscall arch/arm64/kernel/syscall.c:38 [inline]
>  invoke_syscall+0x48/0x114 arch/arm64/kernel/syscall.c:52
>  el0_svc_common.constprop.0+0x44/0xec arch/arm64/kernel/syscall.c:142
>  do_el0_svc+0x6c/0x84 arch/arm64/kernel/syscall.c:181
>  el0_svc+0x44/0xb0 arch/arm64/kernel/entry-common.c:616
>  el0t_64_sync_handler+0x1a4/0x1b0 arch/arm64/kernel/entry-common.c:634
>  el0t_64_sync+0x198/0x19c arch/arm64/kernel/entry.S:581
> ---[ end trace 0000000000000000 ]---
> 
> 
> ---
> This report is generated by a bot. It may contain errors.
> See https://goo.gl/tpsmEJ for more information about syzbot.
> syzbot engineers can be reached at syzkaller@googlegroups.com.
> 
> syzbot will keep track of this issue. See:
> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YmEf8dpSXJeZ2813%40elver.google.com.
