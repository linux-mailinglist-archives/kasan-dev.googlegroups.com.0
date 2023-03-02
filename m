Return-Path: <kasan-dev+bncBCN73WFGVYJRBNHJQSQAMGQEXB4Y3CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 60DFE6A8D28
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Mar 2023 00:43:49 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id w7-20020a056402268700b004bbcdf3751bsf1275197edd.1
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Mar 2023 15:43:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677800629; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZpOZHBQQMtxK9Vtozhf4eGAs27yqVh/XRVn/x4ez8vFYDqgxFLCEHlFQroU8cD0Drk
         2FJGBwMiohl3qhGqiwfu5b9drjd2dxhHkJDv1Qtgh6JjBOwyCOKPbLovotvJSySx0ymd
         dDTqqUnQxoEbEJfy27KAxkP5G3h3Yo6ajOvaQLR/WJJHcfHlXLADuy89eWza5hKwNH09
         v1YV2Jan9ImJVAPw4JDyt/e4sTojvNLVuYYNpdThBK0zxhVO7pdAhlIggw5dtLXLLonb
         WI2F5EudFVYR1ngi2SuFfSGVK9YE1XvDj6htXLaUhCxq8KJy16yH2JPnJ0EyvPDcle2M
         xZYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:user-agent:references:in-reply-to
         :subject:cc:to:from:sender:dkim-signature;
        bh=ySGLXsVpLnb5/dl7e5m/rwklp9UQftwED518r9oh1R0=;
        b=ydjDor6ldi9yC5Eem8vNKpjUWPqykLfUBzsuHVTX/YErxw0dxUt3t6T/tpsVFtxPFT
         PALQR5RzQga85ddjaWMJq/v1h6N+ZHTwTNbk91facc1KTuDWNPmoIk30ZVWxwZW3gn9H
         52NpmPREN8mFRgTt4AJbzDF4NxGaIw1xAhqTLQCp3ui7KP0wH0xOIspwYWZRHVmpJIvD
         HC3ipj+ytDDDzdkv5yajFy3TpyNipxXWxfsUSGdz0L900LHfpMX1VunYAMcKNx2C8WXo
         KK+MXyT0jf4DIubRJvvvJVZSejSaUiEeL0PFgCq2iPxwMJbD6jA+85HavtS0pJixh15e
         F58w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Y8xU3hIS;
       spf=pass (google.com: domain of ying.huang@intel.com designates 192.55.52.115 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1677800629;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:user-agent:references:in-reply-to:subject:cc:to:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ySGLXsVpLnb5/dl7e5m/rwklp9UQftwED518r9oh1R0=;
        b=Kdxpj6LObpexE0F7HW1bV8CBQOIpHrdcIemZggX5A40JuY1n8utXaI+AkKDVSpC6+q
         6UdrqF3tLW60gkBoEqNlX6odHiQDAhQRDjYTIX+K5KX/ljlJpSjPrOgs7u/yt3Ob4f+z
         db7exqp1cmpqBW3hGt3K6T2AZOItzXkNiAzVtQ+95XQ2wcahtmCl8FnefEhHJ4x6wk0K
         nzA9Ikp3S3lijYgjERQXyg5MbCMSxcY855WHMd1J6q95qjyeYy9K+n7pcT4GwYk4IvpL
         MPUCYy5g/rSM6x21pwYrw2llfnKvSrzB47GJotW0881a4jh2xNL3FLYxROO7pZbTJ7Mp
         mv+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1677800629;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:user-agent
         :references:in-reply-to:subject:cc:to:from:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ySGLXsVpLnb5/dl7e5m/rwklp9UQftwED518r9oh1R0=;
        b=2hLMNlT8JXJQ5wTmJsiH7e1/S94odAGEfLQTjnrjl4HJ/ruPcyoE/TFACWbth1p3mk
         hy9gH7gEEz9/lFJCfX6UihZc/GAuhR3Jnt8zDwCicSG6v/Mz06roG1DRC91Fiix7pLdO
         aLpR43cHuh0N35j1L0qNr5XqCqpC7YVecPEjdZr4tf6wEfP0nDemNxfcz6h4O5mwMVaW
         pK2PBnwDo4oa6kF7Euss9Y8uHtHsPq6BVV6USDVzyZGVuHmNeslBSOdn6BJsy9bWFx+Z
         2+muJzMHZocLj1fSGAU11mk+S1GvNT9tRgy7NXI5R5vhhhROm8nf2XnJzg3Bkr9NAbW2
         RZ7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVgiI2qiRVAhianZiJ85nb+0uCNmWJQJbVKYJrxaq/69u5WkrUT
	DlB38Z+kMQOFAYI/be23Swg=
X-Google-Smtp-Source: AK7set+ca4A7grosMFfQ4SU/tWbsosg0RwZaHS/cPkgqTg9LpBelVOBEp6HLvhjpdaHOdLlHY1T/Kw==
X-Received: by 2002:a17:906:b110:b0:8dd:76b6:65b3 with SMTP id u16-20020a170906b11000b008dd76b665b3mr6296146ejy.4.1677800628634;
        Thu, 02 Mar 2023 15:43:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:451:b0:906:3986:efd with SMTP id e17-20020a170906045100b0090639860efdls698186eja.3.-pod-prod-gmail;
 Thu, 02 Mar 2023 15:43:47 -0800 (PST)
X-Received: by 2002:a17:907:a07:b0:8b1:2bde:5c70 with SMTP id bb7-20020a1709070a0700b008b12bde5c70mr15813370ejc.2.1677800626943;
        Thu, 02 Mar 2023 15:43:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677800626; cv=none;
        d=google.com; s=arc-20160816;
        b=O581lRfCZGx7GqPVKfFu/qVZFwA47d35L4K5+xoyhCE8BxpwXj/wIm44d+auT70hhY
         CAPSrSmFX3NZr4LP9E+zRYYSAoutnvD4tu3Lm84QDllMlx7fF3ryzxDH22SSWepoBko9
         o0v10w3D4c+yae3Z6fG+sJftEpXDhK4/K5CGh9jAO6xvvp5UvDase0xxZZDEONioXNeI
         dKbbZVD4AfawIQRQG7+xrsd6m4e02OrqSoxjhT3VL1XffKzaFV7R3WuKDTMxShQpxG/6
         SQnUSpcmw7lHH9OUZ8KqEi/5aale6XmkLmuEOwcV+QCJTUOJfELRa6F3484rRMJeKuw9
         8i+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:user-agent
         :references:in-reply-to:subject:cc:to:from:dkim-signature;
        bh=2//3Owy4gB0hyf64mfOHeFE33C8MptcynoaKhA3yOq0=;
        b=Fvo8q1inyDP6dcJx3g+QZMUP2E5svqK3G+m8pWNEXE+VFNQwoMnN4uYY6i1F/kXavC
         2hCtZH4vyAJbhfMIlHA1qDsp9tkXNdkWcGqMXE4IjFkAMqcRvbKqBKcI6o6PxOjWDmS8
         q2agEvnNbe62YNmzlZAte0/GRnmH8xxH3XMt0CLAetts2mR1z720zKW08sFyjfu1aEFc
         n9nOKayOoiV8/LRhYtlSB40MFMLR8iN2LMK5cSvbQ8wKG1luCNsyqhtpGo4/x+7lNQMn
         PqvpK5DvY+145t3FOLC8Crex4q1Qzhk1FGzOdqBPLILcLPq1quw/qNw4DN+niOL5SsUC
         eQ2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Y8xU3hIS;
       spf=pass (google.com: domain of ying.huang@intel.com designates 192.55.52.115 as permitted sender) smtp.mailfrom=ying.huang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga14.intel.com (mga14.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id qa18-20020a170907869200b008dbae985b18si20228ejc.0.2023.03.02.15.43.46
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Mar 2023 15:43:46 -0800 (PST)
Received-SPF: pass (google.com: domain of ying.huang@intel.com designates 192.55.52.115 as permitted sender) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6500,9779,10637"; a="334914731"
X-IronPort-AV: E=Sophos;i="5.98,229,1673942400"; 
   d="scan'208";a="334914731"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 02 Mar 2023 15:43:44 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10637"; a="739289569"
X-IronPort-AV: E=Sophos;i="5.98,229,1673942400"; 
   d="scan'208";a="739289569"
Received: from yhuang6-desk2.sh.intel.com (HELO yhuang6-desk2.ccr.corp.intel.com) ([10.238.208.55])
  by fmsmga008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 02 Mar 2023 15:43:41 -0800
From: "Huang, Ying" <ying.huang@intel.com>
To: Yang Shi <shy828301@gmail.com>
Cc: syzbot <syzbot+0adf31ecbba886ab504f@syzkaller.appspotmail.com>,  Hugh
 Dickins <hughd@google.com>,  akpm@linux-foundation.org,
  dvyukov@google.com,  elver@google.com,  glider@google.com,
  kasan-dev@googlegroups.com,  linux-kernel@vger.kernel.org,
  linux-mm@kvack.org,  syzkaller-bugs@googlegroups.com
Subject: Re: [syzbot] [mm?] INFO: task hung in write_cache_pages (2)
In-Reply-To: <CAHbLzko8+Ox6Mj6cJZXAHM2i55HQgSXyTUJ0NBQA8jqeLBocMg@mail.gmail.com>
	(Yang Shi's message of "Thu, 2 Mar 2023 12:10:14 -0800")
References: <000000000000e794f505f5e0029c@google.com>
	<CAHbLzko8+Ox6Mj6cJZXAHM2i55HQgSXyTUJ0NBQA8jqeLBocMg@mail.gmail.com>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.1 (gnu/linux)
Date: Fri, 03 Mar 2023 07:42:39 +0800
Message-ID: <87edq690uo.fsf@yhuang6-desk2.ccr.corp.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ying.huang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Y8xU3hIS;       spf=pass
 (google.com: domain of ying.huang@intel.com designates 192.55.52.115 as
 permitted sender) smtp.mailfrom=ying.huang@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

Yang Shi <shy828301@gmail.com> writes:

> On Wed, Mar 1, 2023 at 4:36=E2=80=AFPM syzbot
> <syzbot+0adf31ecbba886ab504f@syzkaller.appspotmail.com> wrote:
>>
>> Hello,
>>
>> syzbot found the following issue on:
>>
>> HEAD commit:    489fa31ea873 Merge branch 'work.misc' of git://git.kerne=
l...
>> git tree:       upstream
>> console output: https://syzkaller.appspot.com/x/log.txt?x=3D1034fef8c800=
00
>> kernel config:  https://syzkaller.appspot.com/x/.config?x=3Dcbfa7a73c540=
248d
>> dashboard link: https://syzkaller.appspot.com/bug?extid=3D0adf31ecbba886=
ab504f
>> compiler:       Debian clang version 15.0.7, GNU ld (GNU Binutils for De=
bian) 2.35.2
>> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=3D16dc6960c8=
0000
>> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=3D16f39d50c800=
00
>>
>> Downloadable assets:
>> disk image: https://storage.googleapis.com/syzbot-assets/8121ff3f8044/di=
sk-489fa31e.raw.xz
>> vmlinux: https://storage.googleapis.com/syzbot-assets/ba8296ba1bf7/vmlin=
ux-489fa31e.xz
>> kernel image: https://storage.googleapis.com/syzbot-assets/6459f50e23f3/=
bzImage-489fa31e.xz
>> mounted in repro: https://storage.googleapis.com/syzbot-assets/845f65381=
08c/mount_1.gz
>>
>> IMPORTANT: if you fix the issue, please add the following tag to the com=
mit:
>> Reported-by: syzbot+0adf31ecbba886ab504f@syzkaller.appspotmail.com
>>
>> INFO: task kworker/u4:0:9 blocked for more than 143 seconds.
>>       Not tainted 6.2.0-syzkaller-10827-g489fa31ea873 #0
>> "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message=
.
>> task:kworker/u4:0    state:D stack:21720 pid:9     ppid:2      flags:0x0=
0004000
>> Workqueue: writeback wb_workfn (flush-7:0)
>> Call Trace:
>>  <TASK>
>>  context_switch kernel/sched/core.c:5304 [inline]
>>  __schedule+0x17d8/0x4990 kernel/sched/core.c:6622
>>  schedule+0xc3/0x180 kernel/sched/core.c:6698
>>  io_schedule+0x8c/0x100 kernel/sched/core.c:8884
>>  folio_wait_bit_common+0x86c/0x12b0 mm/filemap.c:1301
>>  folio_lock include/linux/pagemap.h:952 [inline]
>>  write_cache_pages+0x58f/0x1450 mm/page-writeback.c:2440
>>  mpage_writepages+0x107/0x1d0 fs/mpage.c:653
>>  do_writepages+0x3a6/0x670 mm/page-writeback.c:2551
>>  __writeback_single_inode+0x1c4/0x15e0 fs/fs-writeback.c:1600
>>  writeback_sb_inodes+0x92c/0x1360 fs/fs-writeback.c:1891
>>  __writeback_inodes_wb+0x11b/0x260 fs/fs-writeback.c:1962
>>  wb_writeback+0x51c/0x1080 fs/fs-writeback.c:2067
>>  wb_check_background_flush fs/fs-writeback.c:2133 [inline]
>>  wb_do_writeback fs/fs-writeback.c:2221 [inline]
>>  wb_workfn+0xd80/0x1100 fs/fs-writeback.c:2248
>>  process_one_work+0x915/0x13a0 kernel/workqueue.c:2390
>>  worker_thread+0xa63/0x1210 kernel/workqueue.c:2537
>>  kthread+0x270/0x300 kernel/kthread.c:376
>>  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:308
>>  </TASK>
>> INFO: task kworker/u4:2:41 blocked for more than 143 seconds.
>>       Not tainted 6.2.0-syzkaller-10827-g489fa31ea873 #0
>> "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message=
.
>> task:kworker/u4:2    state:D stack:20480 pid:41    ppid:2      flags:0x0=
0004000
>> Workqueue: writeback wb_workfn (flush-7:5)
>> Call Trace:
>>  <TASK>
>>  context_switch kernel/sched/core.c:5304 [inline]
>>  __schedule+0x17d8/0x4990 kernel/sched/core.c:6622
>>  schedule+0xc3/0x180 kernel/sched/core.c:6698
>>  io_schedule+0x8c/0x100 kernel/sched/core.c:8884
>>  folio_wait_bit_common+0x86c/0x12b0 mm/filemap.c:1301
>>  folio_lock include/linux/pagemap.h:952 [inline]
>>  write_cache_pages+0x58f/0x1450 mm/page-writeback.c:2440
>>  mpage_writepages+0x107/0x1d0 fs/mpage.c:653
>>  do_writepages+0x3a6/0x670 mm/page-writeback.c:2551
>>  __writeback_single_inode+0x1c4/0x15e0 fs/fs-writeback.c:1600
>>  writeback_sb_inodes+0x92c/0x1360 fs/fs-writeback.c:1891
>>  __writeback_inodes_wb+0x11b/0x260 fs/fs-writeback.c:1962
>>  wb_writeback+0x51c/0x1080 fs/fs-writeback.c:2067
>>  wb_check_old_data_flush fs/fs-writeback.c:2167 [inline]
>>  wb_do_writeback fs/fs-writeback.c:2220 [inline]
>>  wb_workfn+0xccb/0x1100 fs/fs-writeback.c:2248
>>  process_one_work+0x915/0x13a0 kernel/workqueue.c:2390
>>  worker_thread+0xa63/0x1210 kernel/workqueue.c:2537
>>  kthread+0x270/0x300 kernel/kthread.c:376
>>  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:308
>>  </TASK>
>> INFO: task kworker/u4:4:75 blocked for more than 144 seconds.
>>       Not tainted 6.2.0-syzkaller-10827-g489fa31ea873 #0
>> "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message=
.
>> task:kworker/u4:4    state:D stack:25088 pid:75    ppid:2      flags:0x0=
0004000
>> Workqueue: writeback wb_workfn (flush-7:1)
>> Call Trace:
>>  <TASK>
>>  context_switch kernel/sched/core.c:5304 [inline]
>>  __schedule+0x17d8/0x4990 kernel/sched/core.c:6622
>>  schedule+0xc3/0x180 kernel/sched/core.c:6698
>>  io_schedule+0x8c/0x100 kernel/sched/core.c:8884
>>  folio_wait_bit_common+0x86c/0x12b0 mm/filemap.c:1301
>>  folio_lock include/linux/pagemap.h:952 [inline]
>>  write_cache_pages+0x58f/0x1450 mm/page-writeback.c:2440
>>  mpage_writepages+0x107/0x1d0 fs/mpage.c:653
>>  do_writepages+0x3a6/0x670 mm/page-writeback.c:2551
>>  __writeback_single_inode+0x1c4/0x15e0 fs/fs-writeback.c:1600
>>  writeback_sb_inodes+0x92c/0x1360 fs/fs-writeback.c:1891
>>  __writeback_inodes_wb+0x11b/0x260 fs/fs-writeback.c:1962
>>  wb_writeback+0x51c/0x1080 fs/fs-writeback.c:2067
>>  wb_check_old_data_flush fs/fs-writeback.c:2167 [inline]
>>  wb_do_writeback fs/fs-writeback.c:2220 [inline]
>>  wb_workfn+0xccb/0x1100 fs/fs-writeback.c:2248
>>  process_one_work+0x915/0x13a0 kernel/workqueue.c:2390
>>  worker_thread+0xa63/0x1210 kernel/workqueue.c:2537
>>  kthread+0x270/0x300 kernel/kthread.c:376
>>  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:308
>>  </TASK>
>> INFO: task syz-executor359:5222 blocked for more than 144 seconds.
>>       Not tainted 6.2.0-syzkaller-10827-g489fa31ea873 #0
>> "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message=
.
>> task:syz-executor359 state:D stack:26576 pid:5222  ppid:5113   flags:0x0=
0004004
>> Call Trace:
>>  <TASK>
>>  context_switch kernel/sched/core.c:5304 [inline]
>>  __schedule+0x17d8/0x4990 kernel/sched/core.c:6622
>>  schedule+0xc3/0x180 kernel/sched/core.c:6698
>>  schedule_preempt_disabled+0x13/0x20 kernel/sched/core.c:6757
>>  rwsem_down_read_slowpath+0x5f4/0x950 kernel/locking/rwsem.c:1086
>>  __down_read_common+0x61/0x2c0 kernel/locking/rwsem.c:1250
>>  mmap_read_lock include/linux/mmap_lock.h:117 [inline]
>>  do_user_addr_fault arch/x86/mm/fault.c:1358 [inline]
>>  handle_page_fault arch/x86/mm/fault.c:1498 [inline]
>>  exc_page_fault+0x558/0x8a0 arch/x86/mm/fault.c:1554
>>  asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:570
>> RIP: 0033:0x7fd6f371b888
>> RSP: 002b:00007ffd6fdf2398 EFLAGS: 00010206
>> RAX: 00007fd6f374ebd0 RBX: 00007fd6f374d1a8 RCX: 0000000000000001
>> RDX: 00007fd6f3688d30 RSI: 0000000000000000 RDI: 00007fd6f374ebd0
>> RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000010
>> R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
>> R13: 0000000000000001 R14: 00007fd6f37543e0 R15: 0000000000000001
>>  </TASK>
>> INFO: task syz-executor359:5223 blocked for more than 144 seconds.
>>       Not tainted 6.2.0-syzkaller-10827-g489fa31ea873 #0
>> "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message=
.
>> task:syz-executor359 state:D stack:24840 pid:5223  ppid:5113   flags:0x0=
0004004
>> Call Trace:
>>  <TASK>
>>  context_switch kernel/sched/core.c:5304 [inline]
>>  __schedule+0x17d8/0x4990 kernel/sched/core.c:6622
>>  schedule+0xc3/0x180 kernel/sched/core.c:6698
>>  io_schedule+0x8c/0x100 kernel/sched/core.c:8884
>>  folio_wait_bit_common+0x86c/0x12b0 mm/filemap.c:1301
>>  folio_lock include/linux/pagemap.h:952 [inline]
>>  write_cache_pages+0x58f/0x1450 mm/page-writeback.c:2440
>>  mpage_writepages+0x107/0x1d0 fs/mpage.c:653
>>  do_writepages+0x3a6/0x670 mm/page-writeback.c:2551
>>  filemap_fdatawrite_wbc+0x125/0x180 mm/filemap.c:390
>>  __filemap_fdatawrite_range mm/filemap.c:423 [inline]
>>  file_write_and_wait_range+0x20f/0x300 mm/filemap.c:781
>>  __generic_file_fsync+0x72/0x190 fs/libfs.c:1132
>>  fat_file_fsync+0x7e/0x190 fs/fat/file.c:191
>>  generic_write_sync include/linux/fs.h:2452 [inline]
>>  generic_file_write_iter+0x2a1/0x310 mm/filemap.c:4090
>>  call_write_iter include/linux/fs.h:1851 [inline]
>>  new_sync_write fs/read_write.c:491 [inline]
>>  vfs_write+0x7b2/0xbb0 fs/read_write.c:584
>>  ksys_write+0x1a0/0x2c0 fs/read_write.c:637
>>  do_syscall_x64 arch/x86/entry/common.c:50 [inline]
>>  do_syscall_64+0x41/0xc0 arch/x86/entry/common.c:80
>>  entry_SYSCALL_64_after_hwframe+0x63/0xcd
>> RIP: 0033:0x7fd6f36ca719
>> RSP: 002b:00007fd6f36762f8 EFLAGS: 00000246 ORIG_RAX: 0000000000000001
>> RAX: ffffffffffffffda RBX: 00007fd6f374f7a0 RCX: 00007fd6f36ca719
>> RDX: 000000000208e24b RSI: 0000000020000080 RDI: 0000000000000004
>> RBP: 00007fd6f371c604 R08: 0000000000000000 R09: 0000000000000000
>> R10: 0000000000000000 R11: 0000000000000246 R12: 00007fd6f371c0e0
>> R13: 0000000020000a80 R14: 0030656c69662f2e R15: 00007fd6f374f7a8
>>  </TASK>
>> INFO: task syz-executor359:5229 blocked for more than 144 seconds.
>>       Not tainted 6.2.0-syzkaller-10827-g489fa31ea873 #0
>> "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message=
.
>> task:syz-executor359 state:D stack:26504 pid:5229  ppid:5113   flags:0x0=
0004004
>> Call Trace:
>>  <TASK>
>>  context_switch kernel/sched/core.c:5304 [inline]
>>  __schedule+0x17d8/0x4990 kernel/sched/core.c:6622
>>  schedule+0xc3/0x180 kernel/sched/core.c:6698
>>  io_schedule+0x8c/0x100 kernel/sched/core.c:8884
>>  folio_wait_bit_common+0x86c/0x12b0 mm/filemap.c:1301
>>  folio_wait_writeback+0xec/0x1f0 mm/page-writeback.c:3127
>>  migrate_folio_unmap mm/migrate.c:1192 [inline]
>>  migrate_pages_batch mm/migrate.c:1685 [inline]
>>  migrate_pages+0x2d50/0x6610 mm/migrate.c:1973
>
> The migration has locked the page, but is waiting for writeback. The
> writeback is waiting for the page lock...
>
> I recalled Huge reported the same bug. There is a patch to solve it,
> but may be not shown in linus's tree yet. And It seems like the
> reproducer is dirtying some files on loop device and calling mbind at
> the same time. This does match the reproducer mentioned by Hugh.

Yes.  We have fixed a bug report similar.  The fix patchset is as
follows,

https://lore.kernel.org/linux-mm/20230224141145.96814-1-ying.huang@intel.co=
m/

It will take some time for it to land in Linus's tree.

Best Regards,
Huang, Ying

>>  do_mbind mm/mempolicy.c:1338 [inline]
>>  kernel_mbind mm/mempolicy.c:1485 [inline]
>>  __do_sys_mbind mm/mempolicy.c:1559 [inline]
>>  __se_sys_mbind+0x75a/0x9c0 mm/mempolicy.c:1555
>>  do_syscall_x64 arch/x86/entry/common.c:50 [inline]
>>  do_syscall_64+0x41/0xc0 arch/x86/entry/common.c:80
>>  entry_SYSCALL_64_after_hwframe+0x63/0xcd
>> RIP: 0033:0x7fd6f36ca719
>> RSP: 002b:00007fd6eb3552e8 EFLAGS: 00000246 ORIG_RAX: 00000000000000ed
>> RAX: ffffffffffffffda RBX: 00007fd6f374f7b0 RCX: 00007fd6f36ca719
>> RDX: 0000000000000000 RSI: 0000000000800000 RDI: 0000000020001000
>> RBP: 00007fd6f371c604 R08: 0000000000000000 R09: 0000000000000002
>> R10: 0000000000000000 R11: 0000000000000246 R12: 00007fd6f371c0e0
>> R13: 0000000020000a80 R14: 0030656c69662f2e R15: 00007fd6f374f7b8
>>  </TASK>
>> INFO: task syz-executor359:5296 blocked for more than 145 seconds.
>>       Not tainted 6.2.0-syzkaller-10827-g489fa31ea873 #0
>> "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message=
.
>> task:syz-executor359 state:D stack:27008 pid:5296  ppid:5112   flags:0x0=
0004004
>> Call Trace:
>>  <TASK>
>>  context_switch kernel/sched/core.c:5304 [inline]
>>  __schedule+0x17d8/0x4990 kernel/sched/core.c:6622
>>  schedule+0xc3/0x180 kernel/sched/core.c:6698
>>  schedule_preempt_disabled+0x13/0x20 kernel/sched/core.c:6757
>>  rwsem_down_read_slowpath+0x5f4/0x950 kernel/locking/rwsem.c:1086
>>  __down_read_common+0x61/0x2c0 kernel/locking/rwsem.c:1250
>>  mmap_read_lock include/linux/mmap_lock.h:117 [inline]
>>  do_user_addr_fault arch/x86/mm/fault.c:1358 [inline]
>>  handle_page_fault arch/x86/mm/fault.c:1498 [inline]
>>  exc_page_fault+0x558/0x8a0 arch/x86/mm/fault.c:1554
>>  asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:570
>> RIP: 0033:0x7fd6f371b888
>> RSP: 002b:00007ffd6fdf2398 EFLAGS: 00010206
>> RAX: 00007fd6f374ebd0 RBX: 00007fd6f374d1a8 RCX: 0000000000000001
>> RDX: 00007fd6f3688d30 RSI: 0000000000000000 RDI: 00007fd6f374ebd0
>> RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000010
>> R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
>> R13: 0000000000000001 R14: 00007fd6f37543e0 R15: 0000000000000001
>>  </TASK>
>> INFO: task syz-executor359:5298 blocked for more than 145 seconds.
>>       Not tainted 6.2.0-syzkaller-10827-g489fa31ea873 #0
>> "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message=
.
>> task:syz-executor359 state:D stack:24840 pid:5298  ppid:5112   flags:0x0=
0004004
>> Call Trace:
>>  <TASK>
>>  context_switch kernel/sched/core.c:5304 [inline]
>>  __schedule+0x17d8/0x4990 kernel/sched/core.c:6622
>>  schedule+0xc3/0x180 kernel/sched/core.c:6698
>>  io_schedule+0x8c/0x100 kernel/sched/core.c:8884
>>  folio_wait_bit_common+0x86c/0x12b0 mm/filemap.c:1301
>>  folio_lock include/linux/pagemap.h:952 [inline]
>>  write_cache_pages+0x58f/0x1450 mm/page-writeback.c:2440
>>  mpage_writepages+0x107/0x1d0 fs/mpage.c:653
>>  do_writepages+0x3a6/0x670 mm/page-writeback.c:2551
>>  filemap_fdatawrite_wbc+0x125/0x180 mm/filemap.c:390
>>  __filemap_fdatawrite_range mm/filemap.c:423 [inline]
>>  file_write_and_wait_range+0x20f/0x300 mm/filemap.c:781
>>  __generic_file_fsync+0x72/0x190 fs/libfs.c:1132
>>  fat_file_fsync+0x7e/0x190 fs/fat/file.c:191
>>  generic_write_sync include/linux/fs.h:2452 [inline]
>>  generic_file_write_iter+0x2a1/0x310 mm/filemap.c:4090
>>  call_write_iter include/linux/fs.h:1851 [inline]
>>  new_sync_write fs/read_write.c:491 [inline]
>>  vfs_write+0x7b2/0xbb0 fs/read_write.c:584
>>  ksys_write+0x1a0/0x2c0 fs/read_write.c:637
>>  do_syscall_x64 arch/x86/entry/common.c:50 [inline]
>>  do_syscall_64+0x41/0xc0 arch/x86/entry/common.c:80
>>  entry_SYSCALL_64_after_hwframe+0x63/0xcd
>> RIP: 0033:0x7fd6f36ca719
>> RSP: 002b:00007fd6f36762f8 EFLAGS: 00000246 ORIG_RAX: 0000000000000001
>> RAX: ffffffffffffffda RBX: 00007fd6f374f7a0 RCX: 00007fd6f36ca719
>> RDX: 000000000208e24b RSI: 0000000020000080 RDI: 0000000000000004
>> RBP: 00007fd6f371c604 R08: 0000000000000000 R09: 0000000000000000
>> R10: 0000000000000000 R11: 0000000000000246 R12: 00007fd6f371c0e0
>> R13: 0000000020000a80 R14: 0030656c69662f2e R15: 00007fd6f374f7a8
>>  </TASK>
>> INFO: task syz-executor359:5304 blocked for more than 145 seconds.
>>       Not tainted 6.2.0-syzkaller-10827-g489fa31ea873 #0
>> "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message=
.
>> task:syz-executor359 state:D stack:26504 pid:5304  ppid:5112   flags:0x0=
0004004
>> Call Trace:
>>  <TASK>
>>  context_switch kernel/sched/core.c:5304 [inline]
>>  __schedule+0x17d8/0x4990 kernel/sched/core.c:6622
>>  schedule+0xc3/0x180 kernel/sched/core.c:6698
>>  io_schedule+0x8c/0x100 kernel/sched/core.c:8884
>>  folio_wait_bit_common+0x86c/0x12b0 mm/filemap.c:1301
>>  folio_wait_writeback+0xec/0x1f0 mm/page-writeback.c:3127
>>  migrate_folio_unmap mm/migrate.c:1192 [inline]
>>  migrate_pages_batch mm/migrate.c:1685 [inline]
>>  migrate_pages+0x2d50/0x6610 mm/migrate.c:1973
>>  do_mbind mm/mempolicy.c:1338 [inline]
>>  kernel_mbind mm/mempolicy.c:1485 [inline]
>>  __do_sys_mbind mm/mempolicy.c:1559 [inline]
>>  __se_sys_mbind+0x75a/0x9c0 mm/mempolicy.c:1555
>>  do_syscall_x64 arch/x86/entry/common.c:50 [inline]
>>  do_syscall_64+0x41/0xc0 arch/x86/entry/common.c:80
>>  entry_SYSCALL_64_after_hwframe+0x63/0xcd
>> RIP: 0033:0x7fd6f36ca719
>> RSP: 002b:00007fd6eb3552e8 EFLAGS: 00000246 ORIG_RAX: 00000000000000ed
>> RAX: ffffffffffffffda RBX: 00007fd6f374f7b0 RCX: 00007fd6f36ca719
>> RDX: 0000000000000000 RSI: 0000000000800000 RDI: 0000000020001000
>> RBP: 00007fd6f371c604 R08: 0000000000000000 R09: 0000000000000002
>> R10: 0000000000000000 R11: 0000000000000246 R12: 00007fd6f371c0e0
>> R13: 0000000020000a80 R14: 0030656c69662f2e R15: 00007fd6f374f7b8
>>  </TASK>
>> INFO: task syz-executor359:5460 blocked for more than 146 seconds.
>>       Not tainted 6.2.0-syzkaller-10827-g489fa31ea873 #0
>> "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message=
.
>> task:syz-executor359 state:D stack:26520 pid:5460  ppid:5115   flags:0x0=
0004004
>> Call Trace:
>>  <TASK>
>>  context_switch kernel/sched/core.c:5304 [inline]
>>  __schedule+0x17d8/0x4990 kernel/sched/core.c:6622
>>  schedule+0xc3/0x180 kernel/sched/core.c:6698
>>  schedule_preempt_disabled+0x13/0x20 kernel/sched/core.c:6757
>>  rwsem_down_read_slowpath+0x5f4/0x950 kernel/locking/rwsem.c:1086
>>  __down_read_common+0x61/0x2c0 kernel/locking/rwsem.c:1250
>>  mmap_read_lock include/linux/mmap_lock.h:117 [inline]
>>  do_user_addr_fault arch/x86/mm/fault.c:1358 [inline]
>>  handle_page_fault arch/x86/mm/fault.c:1498 [inline]
>>  exc_page_fault+0x558/0x8a0 arch/x86/mm/fault.c:1554
>>  asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:570
>> RIP: 0033:0x7fd6f371b888
>> RSP: 002b:00007ffd6fdf2398 EFLAGS: 00010206
>> RAX: 00007fd6f374ebd0 RBX: 00007fd6f374d1a8 RCX: 0000000000000001
>> RDX: 00007fd6f3688d30 RSI: 0000000000000000 RDI: 00007fd6f374ebd0
>> RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000010
>> R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
>> R13: 0000000000000001 R14: 00007fd6f37543e0 R15: 0000000000000001
>>  </TASK>
>> Future hung task reports are suppressed, see sysctl kernel.hung_task_war=
nings
>>
>> Showing all locks held in the system:
>> 3 locks held by kworker/u4:0/9:
>>  #0: ffff8881451bb938 ((wq_completion)writeback){+.+.}-{0:0}, at: proces=
s_one_work+0x77f/0x13a0
>>  #1: ffffc900000e7d20 ((work_completion)(&(&wb->dwork)->work)){+.+.}-{0:=
0}, at: process_one_work+0x7c6/0x13a0 kernel/workqueue.c:2365
>>  #2: ffff88807dfe20e0 (&type->s_umount_key#43){++++}-{3:3}, at: trylock_=
super+0x1f/0xf0 fs/super.c:414
>> 1 lock held by rcu_tasks_kthre/12:
>>  #0: ffffffff8d127cf0 (rcu_tasks.tasks_gp_mutex){+.+.}-{3:3}, at: rcu_ta=
sks_one_gp+0x29/0xd20 kernel/rcu/tasks.h:510
>> 1 lock held by rcu_tasks_trace/13:
>>  #0: ffffffff8d1284f0 (rcu_tasks_trace.tasks_gp_mutex){+.+.}-{3:3}, at: =
rcu_tasks_one_gp+0x29/0xd20 kernel/rcu/tasks.h:510
>> 1 lock held by khungtaskd/28:
>>  #0: ffffffff8d127b20 (rcu_read_lock){....}-{1:2}, at: rcu_lock_acquire+=
0x0/0x30
>> 3 locks held by kworker/u4:2/41:
>>  #0: ffff8881451bb938 ((wq_completion)writeback){+.+.}-{0:0}, at: proces=
s_one_work+0x77f/0x13a0
>>  #1: ffffc90000b27d20 ((work_completion)(&(&wb->dwork)->work)){+.+.}-{0:=
0}, at: process_one_work+0x7c6/0x13a0 kernel/workqueue.c:2365
>>  #2: ffff88801d8680e0 (&type->s_umount_key#43){++++}-{3:3}, at: trylock_=
super+0x1f/0xf0 fs/super.c:414
>> 3 locks held by kworker/u4:4/75:
>>  #0: ffff8881451bb938 ((wq_completion)writeback){+.+.}-{0:0}, at: proces=
s_one_work+0x77f/0x13a0
>>  #1: ffffc900020efd20 ((work_completion)(&(&wb->dwork)->work)){+.+.}-{0:=
0}, at: process_one_work+0x7c6/0x13a0 kernel/workqueue.c:2365
>>  #2: ffff88802c2640e0 (&type->s_umount_key#43){++++}-{3:3}, at: trylock_=
super+0x1f/0xf0 fs/super.c:414
>> 2 locks held by kworker/1:2/2494:
>>  #0: ffff888012472538 ((wq_completion)rcu_gp){+.+.}-{0:0}, at: process_o=
ne_work+0x77f/0x13a0
>>  #1: ffffc9000a86fd20 ((work_completion)(&rew->rew_work)){+.+.}-{0:0}, a=
t: process_one_work+0x7c6/0x13a0 kernel/workqueue.c:2365
>> 2 locks held by getty/4750:
>>  #0: ffff88814a0e2098 (&tty->ldisc_sem){++++}-{0:0}, at: tty_ldisc_ref_w=
ait+0x25/0x70 drivers/tty/tty_ldisc.c:244
>>  #1: ffffc900015802f0 (&ldata->atomic_read_lock){+.+.}-{3:3}, at: n_tty_=
read+0x6ab/0x1db0 drivers/tty/n_tty.c:2177
>> 1 lock held by syz-executor359/5222:
>>  #0: ffff88807d1df698 (&mm->mmap_lock){++++}-{3:3}, at: mmap_read_lock i=
nclude/linux/mmap_lock.h:117 [inline]
>>  #0: ffff88807d1df698 (&mm->mmap_lock){++++}-{3:3}, at: do_user_addr_fau=
lt arch/x86/mm/fault.c:1358 [inline]
>>  #0: ffff88807d1df698 (&mm->mmap_lock){++++}-{3:3}, at: handle_page_faul=
t arch/x86/mm/fault.c:1498 [inline]
>>  #0: ffff88807d1df698 (&mm->mmap_lock){++++}-{3:3}, at: exc_page_fault+0=
x558/0x8a0 arch/x86/mm/fault.c:1554
>> 2 locks held by syz-executor359/5223:
>>  #0: ffff888021e0f768 (&f->f_pos_lock){+.+.}-{3:3}, at: __fdget_pos+0x25=
4/0x2f0 fs/file.c:1046
>>  #1: ffff88802c264460 (sb_writers#9){.+.+}-{0:0}, at: vfs_write+0x26d/0x=
bb0 fs/read_write.c:580
>> 1 lock held by syz-executor359/5229:
>>  #0: ffff88807d1df698 (&mm->mmap_lock){++++}-{3:3}, at: mmap_write_lock =
include/linux/mmap_lock.h:71 [inline]
>>  #0: ffff88807d1df698 (&mm->mmap_lock){++++}-{3:3}, at: do_mbind mm/memp=
olicy.c:1312 [inline]
>>  #0: ffff88807d1df698 (&mm->mmap_lock){++++}-{3:3}, at: kernel_mbind mm/=
mempolicy.c:1485 [inline]
>>  #0: ffff88807d1df698 (&mm->mmap_lock){++++}-{3:3}, at: __do_sys_mbind m=
m/mempolicy.c:1559 [inline]
>>  #0: ffff88807d1df698 (&mm->mmap_lock){++++}-{3:3}, at: __se_sys_mbind+0=
x47d/0x9c0 mm/mempolicy.c:1555
>> 1 lock held by syz-executor359/5296:
>>  #0: ffff88802cd0ae98 (&mm->mmap_lock){++++}-{3:3}, at: mmap_read_lock i=
nclude/linux/mmap_lock.h:117 [inline]
>>  #0: ffff88802cd0ae98 (&mm->mmap_lock){++++}-{3:3}, at: do_user_addr_fau=
lt arch/x86/mm/fault.c:1358 [inline]
>>  #0: ffff88802cd0ae98 (&mm->mmap_lock){++++}-{3:3}, at: handle_page_faul=
t arch/x86/mm/fault.c:1498 [inline]
>>  #0: ffff88802cd0ae98 (&mm->mmap_lock){++++}-{3:3}, at: exc_page_fault+0=
x558/0x8a0 arch/x86/mm/fault.c:1554
>> 2 locks held by syz-executor359/5298:
>>  #0: ffff88807e2b0fe8 (&f->f_pos_lock){+.+.}-{3:3}, at: __fdget_pos+0x25=
4/0x2f0 fs/file.c:1046
>>  #1: ffff88807dfe2460 (sb_writers#9){.+.+}-{0:0}, at: vfs_write+0x26d/0x=
bb0 fs/read_write.c:580
>> 1 lock held by syz-executor359/5304:
>>  #0: ffff88802cd0ae98 (&mm->mmap_lock){++++}-{3:3}, at: mmap_write_lock =
include/linux/mmap_lock.h:71 [inline]
>>  #0: ffff88802cd0ae98 (&mm->mmap_lock){++++}-{3:3}, at: do_mbind mm/memp=
olicy.c:1312 [inline]
>>  #0: ffff88802cd0ae98 (&mm->mmap_lock){++++}-{3:3}, at: kernel_mbind mm/=
mempolicy.c:1485 [inline]
>>  #0: ffff88802cd0ae98 (&mm->mmap_lock){++++}-{3:3}, at: __do_sys_mbind m=
m/mempolicy.c:1559 [inline]
>>  #0: ffff88802cd0ae98 (&mm->mmap_lock){++++}-{3:3}, at: __se_sys_mbind+0=
x47d/0x9c0 mm/mempolicy.c:1555
>> 1 lock held by syz-executor359/5460:
>>  #0: ffff888022485298 (&mm->mmap_lock){++++}-{3:3}, at: mmap_read_lock i=
nclude/linux/mmap_lock.h:117 [inline]
>>  #0: ffff888022485298 (&mm->mmap_lock){++++}-{3:3}, at: do_user_addr_fau=
lt arch/x86/mm/fault.c:1358 [inline]
>>  #0: ffff888022485298 (&mm->mmap_lock){++++}-{3:3}, at: handle_page_faul=
t arch/x86/mm/fault.c:1498 [inline]
>>  #0: ffff888022485298 (&mm->mmap_lock){++++}-{3:3}, at: exc_page_fault+0=
x558/0x8a0 arch/x86/mm/fault.c:1554
>> 2 locks held by syz-executor359/5461:
>>  #0: ffff88801da66ae8 (&f->f_pos_lock){+.+.}-{3:3}, at: __fdget_pos+0x25=
4/0x2f0 fs/file.c:1046
>>  #1: ffff888148d0a460 (sb_writers#9){.+.+}-{0:0}, at: vfs_write+0x26d/0x=
bb0 fs/read_write.c:580
>> 1 lock held by syz-executor359/5467:
>>  #0: ffff888022485298 (&mm->mmap_lock){++++}-{3:3}, at: mmap_write_lock =
include/linux/mmap_lock.h:71 [inline]
>>  #0: ffff888022485298 (&mm->mmap_lock){++++}-{3:3}, at: do_mbind mm/memp=
olicy.c:1312 [inline]
>>  #0: ffff888022485298 (&mm->mmap_lock){++++}-{3:3}, at: kernel_mbind mm/=
mempolicy.c:1485 [inline]
>>  #0: ffff888022485298 (&mm->mmap_lock){++++}-{3:3}, at: __do_sys_mbind m=
m/mempolicy.c:1559 [inline]
>>  #0: ffff888022485298 (&mm->mmap_lock){++++}-{3:3}, at: __se_sys_mbind+0=
x47d/0x9c0 mm/mempolicy.c:1555
>> 1 lock held by syz-executor359/5570:
>>  #0: ffff88807d295298 (&mm->mmap_lock){++++}-{3:3}, at: mmap_read_lock i=
nclude/linux/mmap_lock.h:117 [inline]
>>  #0: ffff88807d295298 (&mm->mmap_lock){++++}-{3:3}, at: do_user_addr_fau=
lt arch/x86/mm/fault.c:1358 [inline]
>>  #0: ffff88807d295298 (&mm->mmap_lock){++++}-{3:3}, at: handle_page_faul=
t arch/x86/mm/fault.c:1498 [inline]
>>  #0: ffff88807d295298 (&mm->mmap_lock){++++}-{3:3}, at: exc_page_fault+0=
x558/0x8a0 arch/x86/mm/fault.c:1554
>> 2 locks held by syz-executor359/5571:
>>  #0: ffff88807838a5e8 (&f->f_pos_lock){+.+.}-{3:3}, at: __fdget_pos+0x25=
4/0x2f0 fs/file.c:1046
>>  #1: ffff88801d868460 (sb_writers#9){.+.+}-{0:0}, at: vfs_write+0x26d/0x=
bb0 fs/read_write.c:580
>> 1 lock held by syz-executor359/5575:
>>  #0: ffff88807d295298 (&mm->mmap_lock){++++}-{3:3}, at: mmap_write_lock =
include/linux/mmap_lock.h:71 [inline]
>>  #0: ffff88807d295298 (&mm->mmap_lock){++++}-{3:3}, at: do_mbind mm/memp=
olicy.c:1312 [inline]
>>  #0: ffff88807d295298 (&mm->mmap_lock){++++}-{3:3}, at: kernel_mbind mm/=
mempolicy.c:1485 [inline]
>>  #0: ffff88807d295298 (&mm->mmap_lock){++++}-{3:3}, at: __do_sys_mbind m=
m/mempolicy.c:1559 [inline]
>>  #0: ffff88807d295298 (&mm->mmap_lock){++++}-{3:3}, at: __se_sys_mbind+0=
x47d/0x9c0 mm/mempolicy.c:1555
>> 1 lock held by syz-executor359/5572:
>>  #0: ffff88807d1dc098 (&mm->mmap_lock){++++}-{3:3}, at: mmap_read_lock i=
nclude/linux/mmap_lock.h:117 [inline]
>>  #0: ffff88807d1dc098 (&mm->mmap_lock){++++}-{3:3}, at: do_user_addr_fau=
lt arch/x86/mm/fault.c:1358 [inline]
>>  #0: ffff88807d1dc098 (&mm->mmap_lock){++++}-{3:3}, at: handle_page_faul=
t arch/x86/mm/fault.c:1498 [inline]
>>  #0: ffff88807d1dc098 (&mm->mmap_lock){++++}-{3:3}, at: exc_page_fault+0=
x558/0x8a0 arch/x86/mm/fault.c:1554
>> 2 locks held by syz-executor359/5573:
>>  #0: ffff888026d84d68 (&f->f_pos_lock){+.+.}-{3:3}, at: __fdget_pos+0x25=
4/0x2f0 fs/file.c:1046
>>  #1: ffff88807b6ac460 (sb_writers#9){.+.+}-{0:0}, at: vfs_write+0x26d/0x=
bb0 fs/read_write.c:580
>> 1 lock held by syz-executor359/5576:
>>  #0: ffff88807d1dc098 (&mm->mmap_lock){++++}-{3:3}, at: mmap_write_lock =
include/linux/mmap_lock.h:71 [inline]
>>  #0: ffff88807d1dc098 (&mm->mmap_lock){++++}-{3:3}, at: do_mbind mm/memp=
olicy.c:1312 [inline]
>>  #0: ffff88807d1dc098 (&mm->mmap_lock){++++}-{3:3}, at: kernel_mbind mm/=
mempolicy.c:1485 [inline]
>>  #0: ffff88807d1dc098 (&mm->mmap_lock){++++}-{3:3}, at: __do_sys_mbind m=
m/mempolicy.c:1559 [inline]
>>  #0: ffff88807d1dc098 (&mm->mmap_lock){++++}-{3:3}, at: __se_sys_mbind+0=
x47d/0x9c0 mm/mempolicy.c:1555
>> 3 locks held by kworker/u4:3/5614:
>>  #0: ffff8881451bb938 ((wq_completion)writeback){+.+.}-{0:0}, at: proces=
s_one_work+0x77f/0x13a0
>>  #1: ffffc90004defd20 ((work_completion)(&(&wb->dwork)->work)){+.+.}-{0:=
0}, at: process_one_work+0x7c6/0x13a0 kernel/workqueue.c:2365
>>  #2: ffff88807b6ac0e0 (&type->s_umount_key#43){++++}-{3:3}, at: trylock_=
super+0x1f/0xf0 fs/super.c:414
>> 3 locks held by kworker/u4:5/6087:
>>  #0: ffff8881451bb938 ((wq_completion)writeback){+.+.}-{0:0}, at: proces=
s_one_work+0x77f/0x13a0
>>  #1: ffffc900055b7d20 ((work_completion)(&(&wb->dwork)->work)){+.+.}-{0:=
0}, at: process_one_work+0x7c6/0x13a0 kernel/workqueue.c:2365
>>  #2: ffff888148d0a0e0 (&type->s_umount_key#43){++++}-{3:3}, at: trylock_=
super+0x1f/0xf0 fs/super.c:414
>> 1 lock held by syz-executor359/12461:
>>  #0: ffffffff8d12d1f8 (rcu_state.exp_mutex){+.+.}-{3:3}, at: exp_funnel_=
lock kernel/rcu/tree_exp.h:293 [inline]
>>  #0: ffffffff8d12d1f8 (rcu_state.exp_mutex){+.+.}-{3:3}, at: synchronize=
_rcu_expedited+0x3a3/0x890 kernel/rcu/tree_exp.h:989
>>
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>
>> NMI backtrace for cpu 0
>> CPU: 0 PID: 28 Comm: khungtaskd Not tainted 6.2.0-syzkaller-10827-g489fa=
31ea873 #0
>> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS =
Google 02/16/2023
>> Call Trace:
>>  <TASK>
>>  __dump_stack lib/dump_stack.c:88 [inline]
>>  dump_stack_lvl+0x1e7/0x2d0 lib/dump_stack.c:106
>>  nmi_cpu_backtrace+0x4e5/0x560 lib/nmi_backtrace.c:113
>>  nmi_trigger_cpumask_backtrace+0x1b4/0x410 lib/nmi_backtrace.c:62
>>  trigger_all_cpu_backtrace include/linux/nmi.h:148 [inline]
>>  check_hung_uninterruptible_tasks kernel/hung_task.c:222 [inline]
>>  watchdog+0x1024/0x1070 kernel/hung_task.c:379
>>  kthread+0x270/0x300 kernel/kthread.c:376
>>  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:308
>>  </TASK>
>> Sending NMI from CPU 0 to CPUs 1:
>> NMI backtrace for cpu 1
>> CPU: 1 PID: 6343 Comm: kworker/u4:9 Not tainted 6.2.0-syzkaller-10827-g4=
89fa31ea873 #0
>> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS =
Google 02/16/2023
>> Workqueue: events_unbound toggle_allocation_gate
>> RIP: 0010:rcu_sync_is_idle include/linux/rcu_sync.h:36 [inline]
>> RIP: 0010:percpu_up_read include/linux/percpu-rwsem.h:105 [inline]
>> RIP: 0010:cpus_read_unlock+0x5f/0x130 kernel/cpu.c:322
>> Code: 85 db 74 1b e8 c2 4f 20 00 89 c3 31 ff 89 c6 e8 87 23 39 00 85
> db 74 5b e8 ce 1f 39 00 eb 05 e8 c7 1f 39 00 8b 1d 41 be a8 0b <31> ff
> 89 de e8 68 23 39 00 85 db 0f 85 8c 00 00 00 e8 ab 1f 39 00
>> RSP: 0018:ffffc90005757b70 EFLAGS: 00000293
>> RAX: ffffffff81538cb2 RBX: 0000000000000000 RCX: ffff888028643a80
>> RDX: 0000000000000000 RSI: 0000000000000001 RDI: 0000000000000000
>> RBP: ffffc90005757c50 R08: ffffffff81538ca9 R09: fffffbfff1ce8d2e
>> R10: 0000000000000000 R11: dffffc0000000001 R12: dffffc0000000000
>> R13: 1ffff1104779cc03 R14: 0000000000000000 R15: 1ffff92000aeaf70
>> FS:  0000000000000000(0000) GS:ffff8880b9900000(0000) knlGS:000000000000=
0000
>> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>> CR2: 00007ffd6fdf0bb8 CR3: 000000000cf30000 CR4: 00000000003506e0
>> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
>> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
>> Call Trace:
>>  <TASK>
>>  toggle_allocation_gate+0xb5/0x250 mm/kfence/core.c:799
>>  process_one_work+0x915/0x13a0 kernel/workqueue.c:2390
>>  worker_thread+0xa63/0x1210 kernel/workqueue.c:2537
>>  kthread+0x270/0x300 kernel/kthread.c:376
>>  ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:308
>>  </TASK>
>>
>>
>> ---
>> This report is generated by a bot. It may contain errors.
>> See https://goo.gl/tpsmEJ for more information about syzbot.
>> syzbot engineers can be reached at syzkaller@googlegroups.com.
>>
>> syzbot will keep track of this issue. See:
>> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
>> syzbot can test patches for this issue, for details see:
>> https://goo.gl/tpsmEJ#testing-patches
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87edq690uo.fsf%40yhuang6-desk2.ccr.corp.intel.com.
