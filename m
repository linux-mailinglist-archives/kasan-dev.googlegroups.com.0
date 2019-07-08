Return-Path: <kasan-dev+bncBCILLLGERUHBBP5XRXUQKGQEQZVGGSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 89BAE6211B
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jul 2019 17:05:37 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id k20sf10661594pgg.15
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jul 2019 08:05:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562598335; cv=pass;
        d=google.com; s=arc-20160816;
        b=KBYEbDPPys6txahPYYyzRMWuWyedlndqLYw+AS8j+juy3PPLOt0B51CIJx7mJG3BLR
         +R3sntkaAfZGWJCM17XfdJbBLoJdB9hA6CVyIXwi0zHPIPSF4OpHdVcCRcaWTHo0qqzf
         rLQUkI9Y2YtDa9EadSt+dX/l3CwDupXfaKSc2CE//a3/GkPPVooXE1jp3JosCg8DnVwk
         waTAe9icu7bKpbZrzYvTJ5Yz3K2ywj84KchP17ovI2b4MgUhVlGsKss16S5Vqn79ECoW
         21ZTw1SsJEda7kW/WFxCyRtQhzCXpH5cDI4qDsODv+WU6JoLZsQK4UFEdttBETODZ+iE
         G/sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:content-disposition
         :mime-version:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xiWNUBJwYbCZJ5X0XfIOuC3pHyMSpgbPYJPFUXNQ4pI=;
        b=aS0DqJ5VhLfOqxpe1ihdd+32R7DzQgiXaqaz2lyjJ3VWb65fcts6PbxGK25SvCmR3Y
         mogbYqDva1i3uxsYjVtA7syTLcufna10exAdbH2c+e0Wtl2iGeNYOG8xSqMjWAVs8H3w
         Pn+cGyq99evVgXBSIuMQf3xZZACCoImR/kUzp4+mYknTiL20fvGIWeDEKhZJZ2Y41WlU
         uQlRnuJElxEGbM+85cHLgXK3AXU56yqi0993egjY1wY1Alvmt20aNEkKjjctv1ttoi4B
         DQMC/MCXS5b1G1JBYkCG4UMmU0CnpAPXX2cZKCB5Z1hX6eAndm4JmcZmfHmoF1nqIN61
         DDKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dennisszhou@gmail.com designates 209.85.222.193 as permitted sender) smtp.mailfrom=dennisszhou@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xiWNUBJwYbCZJ5X0XfIOuC3pHyMSpgbPYJPFUXNQ4pI=;
        b=KYQZrkua03wZR4dQhAQQlk0SfZ4VkLpjumdCtEp92TSLJANG71BlrSJOQ7P8GMw8SZ
         7jvNd8WoddaH49J6lJIrk2TxBkAGUs+jx6CVYpKTeM8Hy7uGL0shUmNxiT2gl4Cl6PhJ
         3rjaGNxNp7Dw3Nwqm0DteT2m0AlB95/nyamscZ7dJwq3mxQb2ztnwnahpHWb5nwQGGZU
         NiPypmot72clsG/p96e4MEe4pi7LctLz4TzmqhusYlkHvTqVVAB9aK1uYoAQLoPNBKqo
         SEUbjNb6FjQVFA35JAbppqZg1zetWrs9BMK1ogcLD1FZOGiHeA6Su8sjHCUiyXd/MVFy
         1/Vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :mime-version:content-disposition:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xiWNUBJwYbCZJ5X0XfIOuC3pHyMSpgbPYJPFUXNQ4pI=;
        b=HzEZ3VfziZSxiLmuq8YICK6MxBOLtmWdsGoLYND6AD5YGNnCqzw0DNg/wpNIl7pizM
         xBNBKxpisNtSEy3OLTYasBko2oGv2xZM53Tlilmu9sdsDxWdGIDBYhXLKKxAWEx3K/P8
         v9yZWAxHtMxlD5T5TwlI20hj2SLsl0DjjLOOjfywQdFmwKpY4avvyj1+bF7MBPwBkqKa
         NjnRCdEvbg1lypqp/QBlsbfrrWLaphkXGHqtqW/oAy9a28qXwZSfcCJhK1rT/kUIIdGQ
         Zv7HE65uG5Vqv82h+BJCJHAuOo6Kng8l+6Z3MeBrbOjIpvJ3nsqlcAWSQ3k0Gc6s0Uzu
         qd4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUwr5iiBGOLRHXuFweOl91acCtsiJ0zRbhOhTsqfyBtU5/m4Adf
	oU7l9UF/zgb/HkKR+PRpxFA=
X-Google-Smtp-Source: APXvYqxRITzb3GV8Z1OMCePNiPe6A16W9xos1RHtGsz8BzxlesSV2HkdQvGbjl8daaVw73DYJ5hA+g==
X-Received: by 2002:a17:90b:8d2:: with SMTP id ds18mr26903788pjb.132.1562598335844;
        Mon, 08 Jul 2019 08:05:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:63c1:: with SMTP id x184ls2843786pfb.5.gmail; Mon, 08
 Jul 2019 08:05:35 -0700 (PDT)
X-Received: by 2002:a65:48c3:: with SMTP id o3mr24930476pgs.70.1562598335454;
        Mon, 08 Jul 2019 08:05:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562598335; cv=none;
        d=google.com; s=arc-20160816;
        b=MgLP0TF90GAB1U8ROOLubxbuNdPvQtkzIoiKINt9+N/yHyAxGOInxTIs4CKm/5fvZV
         eL154EmT94uFQLIuhVFDhvn/cTPpX+h3mgMWR0DfyQwB/IkFaek2YtwgF6UJo5pTIqjR
         RdlG3eOE+AaqHS458G5f4hf3LC+X4s2/9fVKwGIa7KKoVVUnGhqxwhJDjPWNthUd/Y7I
         2x5ZbAtXllNtumUQZ7IPA6PCxszqJ4p/f0PU38eFSQpC5YXuYMZDluE429KVqLvQcq5e
         TBXiQlY130BsgxYYl3Pwm7rlOpM14DDH7vUJOy64x4LpK0onmOARbAyU7IkoA8W4GSnW
         EUxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:content-disposition:mime-version:message-id:subject:cc
         :to:from:date;
        bh=20M7KDomLReO6Q78cKUuYTnw9RHJCW0JDgM2rMub9R0=;
        b=WV4C8SUgbyXtX79LgFLMoOpOCEQyzk07F2Yo4Pwx/pTi4u+5hyabUHW5UflhlXtIuw
         brAeA+yA0gAmpNtwb3HS1ISRVfJ57rkEUZoRj+2czTsb3dFSFdHQSjcNH2FiWEFjpC00
         VenJWMz5p0/agRoLuCloReyu1VgncehXAxjOQaXjMb3Qg23HWpZEGao3jkJSoZu6LxqX
         zKzVDAexO0hYZZWnKhC8jX/57nuS7+6KtpkjAoTUjal3Hf/xeZS1kZtk+f1avvPg6xl+
         pr7WFrR7WYvm17P3maud3EgmtQBU9nZbX/l2yarXh5WYDxxo70DCK7DawVyvQUnPucJ+
         0wwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dennisszhou@gmail.com designates 209.85.222.193 as permitted sender) smtp.mailfrom=dennisszhou@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-qk1-f193.google.com (mail-qk1-f193.google.com. [209.85.222.193])
        by gmr-mx.google.com with ESMTPS id b24si107369pjq.1.2019.07.08.08.05.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jul 2019 08:05:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of dennisszhou@gmail.com designates 209.85.222.193 as permitted sender) client-ip=209.85.222.193;
Received: by mail-qk1-f193.google.com with SMTP id d79so9252006qke.11
        for <kasan-dev@googlegroups.com>; Mon, 08 Jul 2019 08:05:35 -0700 (PDT)
X-Received: by 2002:a05:620a:68c:: with SMTP id f12mr14608641qkh.197.1562598334612;
        Mon, 08 Jul 2019 08:05:34 -0700 (PDT)
Received: from dennisz-mbp ([2620:10d:c091:500::3:8b5a])
        by smtp.gmail.com with ESMTPSA id g54sm8989306qtc.61.2019.07.08.08.05.33
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jul 2019 08:05:33 -0700 (PDT)
Date: Mon, 8 Jul 2019 11:05:32 -0400
From: Dennis Zhou <dennis@kernel.org>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Cc: Tejun Heo <tj@kernel.org>, Kefeng Wang <wangkefeng.wang@huawei.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: kasan: paging percpu + kasan causes a double fault
Message-ID: <20190708150532.GB17098@dennisz-mbp>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: DennisSZhou@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dennisszhou@gmail.com designates 209.85.222.193 as
 permitted sender) smtp.mailfrom=dennisszhou@gmail.com;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hi Andrey, Alexander, and Dmitry,

It was reported to me that when percpu is ran with param
percpu_alloc=page or the embed allocation scheme fails and falls back to
page that a double fault occurs.

I don't know much about how kasan works, but a difference between the
two is that we manually reserve vm area via vm_area_register_early().
I guessed it had something to do with the stack canary or the irq_stack,
and manually mapped the shadow vm area with kasan_add_zero_shadow(), but
that didn't seem to do the trick.

RIP resolves to the fixed_percpu_data declaration.

Double fault below:
[    0.000000] PANIC: double fault, error_code: 0x0
[    0.000000] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.2.0-rc7-00007-ge0afe6d4d12c-dirty #299
[    0.000000] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.0-2.el7 04/01/2014
[    0.000000] RIP: 0010:no_context+0x38/0x4b0
[    0.000000] Code: df 41 57 41 56 4c 8d bf 88 00 00 00 41 55 49 89 d5 41 54 49 89 f4 55 48 89 fd 4c8
[    0.000000] RSP: 0000:ffffc8ffffffff28 EFLAGS: 00010096
[    0.000000] RAX: dffffc0000000000 RBX: ffffc8ffffffff50 RCX: 000000000000000b
[    0.000000] RDX: fffff52000000030 RSI: 0000000000000003 RDI: ffffc90000000130
[    0.000000] RBP: ffffc900000000a8 R08: 0000000000000001 R09: 0000000000000000
[    0.000000] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000003
[    0.000000] R13: fffff52000000030 R14: 0000000000000000 R15: ffffc90000000130
[    0.000000] FS:  0000000000000000(0000) GS:ffffc90000000000(0000) knlGS:0000000000000000
[    0.000000] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    0.000000] CR2: ffffc8ffffffff18 CR3: 0000000002e0d001 CR4: 00000000000606b0
[    0.000000] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[    0.000000] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[    0.000000] Call Trace:
[    0.000000] Kernel panic - not syncing: Machine halted.
[    0.000000] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.2.0-rc7-00007-ge0afe6d4d12c-dirty #299
[    0.000000] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.11.0-2.el7 04/01/2014
[    0.000000] Call Trace:
[    0.000000]  <#DF>
[    0.000000]  dump_stack+0x5b/0x90
[    0.000000]  panic+0x17e/0x36e
[    0.000000]  ? __warn_printk+0xdb/0xdb
[    0.000000]  ? spurious_kernel_fault_check+0x1a/0x60
[    0.000000]  df_debug+0x2e/0x39
[    0.000000]  do_double_fault+0x89/0xb0
[    0.000000]  double_fault+0x1e/0x30
[    0.000000] RIP: 0010:no_context+0x38/0x4b0
[    0.000000] Code: df 41 57 41 56 4c 8d bf 88 00 00 00 41 55 49 89 d5 41 54 49 89 f4 55 48 89 fd 4c8
[    0.000000] RSP: 0000:ffffc8ffffffff28 EFLAGS: 00010096
[    0.000000] RAX: dffffc0000000000 RBX: ffffc8ffffffff50 RCX: 000000000000000b
[    0.000000] RDX: fffff52000000030 RSI: 0000000000000003 RDI: ffffc90000000130
[    0.000000] RBP: ffffc900000000a8 R08: 0000000000000001 R09: 0000000000000000
[    0.000000] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000003
[ 0.000000] R13: fffff52000000030 R14: 0000000000000000 R15: ffffc90000000130

Thanks,
Dennis

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190708150532.GB17098%40dennisz-mbp.
For more options, visit https://groups.google.com/d/optout.
