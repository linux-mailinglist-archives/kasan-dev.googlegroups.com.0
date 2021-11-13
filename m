Return-Path: <kasan-dev+bncBCSMHHGWUEMBBDMIXWGAMGQEPMBTA5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id D36FD44F145
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Nov 2021 05:50:22 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id p13-20020a63c14d000000b002da483902b1sf5879437pgi.12
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Nov 2021 20:50:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636779021; cv=pass;
        d=google.com; s=arc-20160816;
        b=BWORMjus++KGE/bKpz5M2Up72q+cDhT2HzyIWo/78ADNGbDdfocgTz9RJp5R+yG4Fb
         K625JcXjrS+tvjuTl+yn0hu2gD91xjWnsPk4PoISW3A7YS5hRkGZxxnJDR1TSF1mTdJV
         5cFORrqppsMLWtJTIXJApS2OFttx0zxeE3/6rWoaTKT5gBXtws9rRZA7Oy66eXDRgbWQ
         5aOwJdzvBhPU/hVeKlJ/B/38iUGcYgKgCYqG0xbyXmpjaIJjulF+0VYxBibGOfG2TDJD
         OT9V+1zz7g5lh3fXSPEGE0BUyj8kfqrLyS8FAOzkJfNGmMEogSUUFUNDRxRjDZvVerUf
         bgQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=E5+v9xfsPXKkmFWKi3fwEeey5MyUPnxv0HYi8bD4sBI=;
        b=EXOXEqv4fCxQ7/V5ZSouzri5T83vZKB7zv/WAY21cBvwcs5mR8GK3H3LSjpzN3T7Pv
         wiV8kS50ESWy1Jml3Tu1Qlaf+I4+otlwgI+5hqtzmUFM3eqZY39FXzKFQ+3Oh/IGjBg6
         MkQWtDYe3FBBolrUJ+TGgwyjh3GXyWHee2Y29SNpKGrs88W73toxIWirG0iOv8jhS/ZD
         z37qKwnJWaq3lyaeb+gB9C0Gcw7vVU/EEfVsSAVSZQwvGkpZYdX2pL9YUvTD8KpEAvPi
         yYhGpbcBvg0cx/vOzunDp1BPsezS5YQszqybgX79GGvJvEkS7jJaaaWoQoFetXdAS1G4
         qJ+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=r2xJraid;
       spf=pass (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.38 as permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=E5+v9xfsPXKkmFWKi3fwEeey5MyUPnxv0HYi8bD4sBI=;
        b=lxRxs5CTUlSSw11UzJ7OKh5rsDaIGlP5n9P7DN/JmEgVbP9Yql5hBdwecdzRZBppXH
         5reCn0wgIgeUfPAK7fh0oxgruKkvSREh8mPVwqhihHUSTCAT1k+DQcVka7RIPMiWS7HU
         MFWO+5DYi+Jl9C4DwawaSzk7GLv7ARFIUauy0lO+JhRV/vkw4bP6C4qz4s7+BeI20d7T
         /CHKaI4c1tDZX9KACmdhRbpp62QA1aIicI0KRNYsmnDSX2vkBG++lFACVbZLPw6v2yxk
         e+U6Ey3HZ4MTbPiDghh6A/x2xtwzfLd5M69yPJRtZo4jAepQEg/N/BuOqvEFKxG60wxr
         R3yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E5+v9xfsPXKkmFWKi3fwEeey5MyUPnxv0HYi8bD4sBI=;
        b=y1M4OEgo7UT+YX1sBMa+XYF1xfkLJK3BxdIiCBbWamKScFbjBlHKvGfEMx4K1vK6+W
         f5p0wXfXOrYGB99ow4fBigjpFToa/b/59VxcPbbam5u3XVXVDjwNE+EqOVbhcURB8J47
         uCT1LYZbJONSMUyXJhF1QU330vvhW/2UX56sp4G5sH8rhfOOHmEQ5VRgkhry4aup3tgN
         IlhThS8Lb26RDdC9vmIoZ0jVs2ApCuGgiZSt8HBl1r1qf+j9aXuMia9pofSz9c4LOzrn
         tOpVZhiENS9VXFrMNmDjMSDF0S+m1uX8+31DK/0q1/Th91VZFCmTMAsc4V5cAE6X9Mqx
         6Siw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Y97JO+WjjPG3QHoKkvlPFa3uwaL3u0Uph/BDwnFz4IjJ9W4sG
	xHIwE1ekEGoc09340NJcHAk=
X-Google-Smtp-Source: ABdhPJz6N6GZHqEbbALEyPWI2G1ZdKnxAttdTIbHTf3SQTONGldvImMftNTlZFMrUm3voeidTgcUpg==
X-Received: by 2002:a63:9f1a:: with SMTP id g26mr13334639pge.170.1636779021171;
        Fri, 12 Nov 2021 20:50:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4105:: with SMTP id u5ls4335817pjf.2.gmail; Fri, 12
 Nov 2021 20:50:20 -0800 (PST)
X-Received: by 2002:a17:90a:af97:: with SMTP id w23mr24482240pjq.128.1636779020548;
        Fri, 12 Nov 2021 20:50:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636779020; cv=none;
        d=google.com; s=arc-20160816;
        b=KspuRAi/hWtwyO75C0JSWMG79gzQNZlf0JyqvmQCv25K2rzpx1ZR8Jyy50NXmqclr4
         ciX0gaZpscc2CQaKRp5r7IiaoFVXMlID91UYa0UzKFxGHTHmVO2saBjTLo9/ABLMU881
         rkZdFrtVUa63mHH2F0pmmQNBLKFjgaVV/+jecd524JvPiqTmbjHYNac4PNg3HzJl6l0x
         f+xpBfcjWTfLDHVlTJuKZKedr+bKCtVztjHB2hAjFfxdZQcNsDDfKEL3VIc5U+XFp22S
         zGKkMSGbBj3crFy+0a5TRei/aantwxLPTiFmOW225lUvrWI9gRDMfAF7+Qs1ypBogZWl
         v8+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=9Z7JEgNqK69mdItEfNZmsW5+aKBPzFg+GccRl7MFlYo=;
        b=QQ3e8FRvUatXY2BzRspNNu8BOenjGfeqVbrCVFsNV0VUDRUHMgdZUE9fdOkoj+QeKh
         a/BhTvCGHCXQU7KGt80pXqdVVs6RvE1WMkx4Ot3qDNrpJXDvBp8GzFv/O+k/Mc22Nwji
         1vGr17EQWn7yV9jFjzIHMZbb1+leLSCURU7G6KghYwxFUHosgFg0Kc7EiwxdOOwJEzcp
         6P43ZnrBjnee+mufGKvKfZuMUx3DaM8f78jbLmzPYKKvVenE8o0/HhdLnmEJBfLuJbDZ
         xXB4ZFyr0zp2nelqx0QjD8kHsQuTeZAoSeHlXzmzt0U1bbagxzI8ckd8cLZWQA6uQ4Kf
         Ks1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=r2xJraid;
       spf=pass (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.38 as permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from alexa-out-sd-01.qualcomm.com (alexa-out-sd-01.qualcomm.com. [199.106.114.38])
        by gmr-mx.google.com with ESMTPS id f6si5805pgh.2.2021.11.12.20.50.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Nov 2021 20:50:20 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.38 as permitted sender) client-ip=199.106.114.38;
Received: from unknown (HELO ironmsg05-sd.qualcomm.com) ([10.53.140.145])
  by alexa-out-sd-01.qualcomm.com with ESMTP; 12 Nov 2021 20:50:19 -0800
X-QCInternal: smtphost
Received: from nasanex01c.na.qualcomm.com ([10.47.97.222])
  by ironmsg05-sd.qualcomm.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Nov 2021 20:50:19 -0800
Received: from nalasex01a.na.qualcomm.com (10.47.209.196) by
 nasanex01c.na.qualcomm.com (10.47.97.222) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.922.19; Fri, 12 Nov 2021 20:50:19 -0800
Received: from qian-HP-Z2-SFF-G5-Workstation (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.922.19; Fri, 12 Nov 2021 20:50:18 -0800
Date: Fri, 12 Nov 2021 23:50:16 -0500
From: Qian Cai <quic_qiancai@quicinc.com>
To: Will Deacon <will@kernel.org>, Catalin Marinas <catalin.marinas@arm.com>,
	Mark Rutland <mark.rutland@arm.com>
CC: <linux-arm-kernel@lists.infradead.org>, Dmitry Vyukov
	<dvyukov@google.com>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Valentin Schneider <valentin.schneider@arm.com>
Subject: KASAN + CPU soft-hotplug = stack-out-of-bounds at cpuinfo_store_cpu
Message-ID: <YY9ECKyPtDbD9q8q@qian-HP-Z2-SFF-G5-Workstation>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01a.na.qualcomm.com (10.52.223.231) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-Original-Sender: quic_qiancai@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcdkim header.b=r2xJraid;       spf=pass
 (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.38 as
 permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
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

FYI, running CPU soft-hotplug with KASAN on arm64 defconfig will
always trigger a stack-out-of-bounds below. I am not right sure where
exactly KASAN pointed at, so I am just doing the brute-force
bisect. The progress so far:

# git bisect log
git bisect start
# bad: [e73f0f0ee7541171d89f2e2491130c7771ba58d3] Linux 5.14-rc1
git bisect bad e73f0f0ee7541171d89f2e2491130c7771ba58d3
# good: [62fb9874f5da54fdb243003b386128037319b219] Linux 5.13
git bisect good 62fb9874f5da54fdb243003b386128037319b219
# bad: [e058a84bfddc42ba356a2316f2cf1141974625c9] Merge tag 'drm-next-2021-07-01' of git://anongit.freedesktop.org/drm/drm
git bisect bad e058a84bfddc42ba356a2316f2cf1141974625c9
# bad: [a6eaf3850cb171c328a8b0db6d3c79286a1eba9d] Merge tag 'sched-urgent-2021-06-30' of git://git.kernel.org/pub/scm/linux/kernel/git/tip/tip
git bisect bad a6eaf3850cb171c328a8b0db6d3c79286a1eba9d
# bad: [31e798fd6f0ff0acdc49c1a358b581730936a09a] Merge tag 'media/v5.14-1' of git://git.kernel.org/pub/scm/linux/kernel/git/mchehab/linux-media
git bisect bad 31e798fd6f0ff0acdc49c1a358b581730936a09a

I am going to test the "arm64-upstream" merge request next which has
some interesting arm64/cpuinfo patches.

 BUG: KASAN: stack-out-of-bounds in vsnprintf
 Read of size 8 at addr ffff800016297db8 by task swapper/0/0

 CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.15.0-next-20211110 #157
 Hardware name: MiTAC RAPTOR EV-883832-X3-0001/RAPTOR, BIOS 1.6 06/28/2020
 Call trace:
  dump_backtrace
  show_stack
  dump_stack_lvl
  print_address_description.constprop.0
  kasan_report
  __asan_report_load8_noabort
  vsnprintf
  vsnprintf at /root/linux-next/lib/vsprintf.c:2807
  vprintk_store
  vprintk_store at /root/linux-next/kernel/printk/printk.c:2138 (discriminator 5)
  vprintk_emit
  vprintk_emit at /root/linux-next/kernel/printk/printk.c:2232
  vprintk_default
  vprintk_default at /root/linux-next/kernel/printk/printk.c:2260
  vprintk
  vprintk at /root/linux-next/kernel/printk/printk_safe.c:50
  _printk
  printk at /root/linux-next/kernel/printk/printk.c:2264
  __cpuinfo_store_cpu
  __cpuinfo_store_cpu at /root/linux-next/arch/arm64/kernel/cpuinfo.c:412
  cpuinfo_store_cpu
  cpuinfo_store_cpu at /root/linux-next/arch/arm64/kernel/cpuinfo.c:418
  secondary_start_kernel
  secondary_start_kernel at /root/linux-next/arch/arm64/kernel/smp.c:241
  __secondary_switched


 addr ffff800016297db8 is located in stack of task swapper/0/0 at offset 136 in frame:
  _printk

 this frame has 1 object:
  [32, 64) 'args'

 Memory state around the buggy address:
  ffff800016297c80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  ffff800016297d00: 00 00 00 00 00 00 f1 f1 f1 f1 00 00 00 00 f3 f3
 >ffff800016297d80: f3 f3 00 00 00 00 f3 f3 00 00 00 00 00 00 00 00
                                         ^
  ffff800016297e00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  ffff800016297e80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YY9ECKyPtDbD9q8q%40qian-HP-Z2-SFF-G5-Workstation.
