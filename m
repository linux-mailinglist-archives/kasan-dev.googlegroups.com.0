Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY6X4SJAMGQENMYDESQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A10850269A
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Apr 2022 10:25:08 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id p31-20020a05600c1d9f00b0038ed0964a90sf3424487wms.4
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Apr 2022 01:25:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650011108; cv=pass;
        d=google.com; s=arc-20160816;
        b=fZbxyjQ3JBOY8jBvUxsLUk6UE4EjZ5jhV+lrN0PTLtqBfdofVO6OPgM9lEi8tKQ1bC
         GJDmnh08h1tED9d4NOxsGwPsXp8MGJgr41PLOYY79kaTL/5/8Cp2n2kQpgmo+McWGifQ
         yeMLh99tAscPyqLOqoWNKmSWHyCpmmSqnPzxyjw01ubKGhiU5Fylsy3XX/RyvBiJ+ohP
         Mi48xu5IuUAP8f0KEStAZFZxNIaatCa4Z2ljiMlF62JAsaziuFfOuJhXS279JsoKyrVf
         JoUsNkDUQxoAIbOhhPKoKxHOny35wZzzREKQhA6NHlyj2L9YXZbVS6rW0Jt2qX1i5O19
         Uk9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=PB6G5s43JLAgaS3gJ1K0XwtA+ea8gTPthfvM3A9Oow0=;
        b=YvAmC/zdcmH+dUTUhHVeTkN5KyOFK9Tthb1k68n2XfKxzHoozwpfP0hrbiRONz2h7d
         jQTUz/2SQDaLsuaEH+0z3210nhV/nO7xsr2xwOhfE5BwnELaQDMxKT34DMdMWjq2j1P2
         hi8TCoENsTU2UuKwplGffBzBUoLiuCZlLFmzOdnHyFmoEsDiuFGw3F4V3d43Rwb3Wk4q
         +7Gukk2kUAt4B0LzZNx7CzM2fXiBupQBjy4j8AItutGmE9o++h5MZd0SDydpCmJK/HC2
         ZK2GIbZIc66clRuea7eWuhV/3JBOl2LZuvgcv5lCS/iCOjzDKaSPMciK/ipF5bjYaerv
         klzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HSwleyKR;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=PB6G5s43JLAgaS3gJ1K0XwtA+ea8gTPthfvM3A9Oow0=;
        b=K2BrlL2g3FCV2kEYGfTX52uwQ2JwJ2cOgToTZIkiluMT6+hEumRQ9xb8RKCkT17zOX
         VrgxBH4er7bLZczAKHpr5yliqITNXmwe8uQw53jLkQryfvrJ0Q9sYb0CeQ+gbCOntwEN
         iP0b3L7w//N0IhFiSvtURMJpi3z1CEz91IbcN6DgIRyYauKagy6zof0Nddsqukj2hM/p
         629vSGMFfLMq4dqDB4a4aYwE7up9r/FGlg8bTgTqOS00PJHUftGVkxxwf+X4IqZuWs1a
         tQRcYGFrOim0K0zc4mPfPCOVK/Zj9+9NhiAV1RCc0g0LOBsgaFSU0rB/4J5UK4QhHMoj
         B1hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PB6G5s43JLAgaS3gJ1K0XwtA+ea8gTPthfvM3A9Oow0=;
        b=2SjPOA2crns5TfvOEYEEIFBCD2C3esJWMXbSn0LFk7+Up+CPI7t0IieZ7e2AJY3yvU
         qemfgHtuzj9ETNkRi3l9128T+k5Ue4DCqkOqxcavypSrkMkDZFw76MU+6wj+9VUV3rMX
         wbC8JMj+O+eSKFJ+UefBbyuBMBms5GJYJSDdMShWEbfLYjSWzL2ob7Kk0vPcGKJcEh/W
         T01a9CO18Fgsh2Ou9V2nuSZ+1OLW8JQkzvHtVoRufNGMGDh1CW1yWNftdNjEP3CvMVkn
         XJGIRJ+dhHs3LqruWlb7VXEAwZjArR8G2cWR6a1B8wgZ3xp2ifeRZh+vI8krS+GyWMLZ
         kD1w==
X-Gm-Message-State: AOAM530aU9arPY5JvMX1XIWAMqT5bHzD55VMu6dxWHBIHIVrfdaMvQDC
	o+ab9Wx8tot2T4MUWaRzBtc=
X-Google-Smtp-Source: ABdhPJyKFsb0vhO83QWOFhObd4/K5Fwo9uMyR70FuKRU4qElb5/1x5UnhNPsIRwPiBW4xfRTURvlow==
X-Received: by 2002:adf:eb12:0:b0:207:b333:5e7d with SMTP id s18-20020adfeb12000000b00207b3335e7dmr4868575wrn.585.1650011107749;
        Fri, 15 Apr 2022 01:25:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2747:0:b0:381:80e8:be59 with SMTP id n68-20020a1c2747000000b0038180e8be59ls3604991wmn.1.gmail;
 Fri, 15 Apr 2022 01:25:06 -0700 (PDT)
X-Received: by 2002:a7b:c201:0:b0:38f:f7f5:f6db with SMTP id x1-20020a7bc201000000b0038ff7f5f6dbmr2275989wmi.191.1650011106581;
        Fri, 15 Apr 2022 01:25:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650011106; cv=none;
        d=google.com; s=arc-20160816;
        b=aQRXYw48k0nd6NTxSL4JnpnvVKT2+XLMpZNCkzXOXsFfq92Nx8KuoNykyQS5iHCmzk
         ZoJniuiivkiJxw8EdQVU4YwDHNy7GdoflD4bKuv97DaSIee0fn+w7sx07mA/izdCBDDZ
         a9QgMxAvMs2SyZIiQQuWHWUfq0SUHQFooVZsP3FgThUSSCkFuyBFscowqebk13RAMsUh
         BNGr4WlNnNKs2xicD/vcaeF8hi9r161I2SVu9CYueKLdO8Vmqs4cIIEEq1VT3L8jdfK9
         f5zsVp2Xm7qShmkoJ6py81B6WkTAeY6TmRvPyQM0eZ+TO1lP7AU/pRnMSJGwowvIFKG5
         qzYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=fVUrBKGjZU0u3Zs9QEQDJ4oPemzJ+nL7yLHZVhKUceQ=;
        b=M3wAjBJsm3ks9NzESVp+AswSe500fyhOwojDqk2Spur7+vR+8kA/BwiMJ4VFObAtHf
         ijCVfR2f9TM8cnWyJrWUBy7N1bWR1SG6XhYx5x3A5p5IWLjPx/+O+NBMrWZ/Mee7JFif
         Crf6q2vr0Tdw8FNV6L6C4VgG0mfREVceNkxUwEUpBjs+3t758dIGe6faAHLOPX/TM6dr
         Y6ysJsTqTE+x28pKXR9Eq8DvyB3vwTt5nug8KXFaQDO8+UJIGoYgSIZzVRRUPBIZ/6jw
         pwCw7FMov5RVISPEteAyAw2F2L/5Jrg02loH5Ur21E6f7jH+iKlUw0GlqbD6oN2YnWyZ
         x5qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HSwleyKR;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id az13-20020adfe18d000000b00207bbe754f2si48873wrb.7.2022.04.15.01.25.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Apr 2022 01:25:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id v64-20020a1cac43000000b0038cfd1b3a6dso7347957wme.5
        for <kasan-dev@googlegroups.com>; Fri, 15 Apr 2022 01:25:06 -0700 (PDT)
X-Received: by 2002:a7b:c1cc:0:b0:38e:b876:95d8 with SMTP id a12-20020a7bc1cc000000b0038eb87695d8mr2287618wmj.57.1650011106062;
        Fri, 15 Apr 2022 01:25:06 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:dcf7:562:ed76:3997])
        by smtp.gmail.com with ESMTPSA id p125-20020a1c2983000000b0038e6c62f527sm5172110wmp.14.2022.04.15.01.25.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Apr 2022 01:25:05 -0700 (PDT)
Date: Fri, 15 Apr 2022 10:24:59 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Aleksandr Nogikh <nogikh@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, dvyukov@google.com,
	andreyknvl@gmail.com, glider@google.com, tarasmadan@google.com,
	bigeasy@linutronix.de
Subject: Re: [PATCH v3] kcov: don't generate a warning on vm_insert_page()'s
 failure
Message-ID: <Ylkr2xrVbhQYwNLf@elver.google.com>
References: <20220401182512.249282-1-nogikh@google.com>
 <20220414142457.d22ce3a11920dc943001d737@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220414142457.d22ce3a11920dc943001d737@linux-foundation.org>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=HSwleyKR;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::336 as
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

On Thu, Apr 14, 2022 at 02:24PM -0700, Andrew Morton wrote:
> On Fri,  1 Apr 2022 18:25:12 +0000 Aleksandr Nogikh <nogikh@google.com> wrote:
> 
> > vm_insert_page()'s failure is not an unexpected condition, so don't do
> > WARN_ONCE() in such a case.
> > 
> > Instead, print a kernel message and just return an error code.
> 
> (hm, I thought I asked this before but I can't find it)
> 
> Under what circumstances will this failure occur?

It looks like syzbot was able to generate an OOM situation:

 | [  599.515700][T23028] oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=syz1,mems_allowed=0-1,oom_memcg=/syz1,task_memcg=/syz1,task=syz-executor.1,pid=23028,uid=0
 | [  599.537757][T23028] Memory cgroup out of memory: Killed process 23028 (syz-executor.1) total-vm:56816kB, anon-rss:436kB, file-rss:8888kB, shmem-rss:48kB, UID:0 pgtables:88kB oom_score_adj:1000
 | [  599.615664][T23028] ------------[ cut here ]------------
 | [  599.652858][T23028] vm_insert_page() failed
 | [  599.662598][T23028] WARNING: CPU: 0 PID: 23028 at kernel/kcov.c:479 kcov_mmap+0xbe/0xe0
 | [  599.900577][T23028] Modules linked in:
 | [  599.904480][T23028] CPU: 1 PID: 23028 Comm: syz-executor.1 Tainted: G        W         5.17.0-syzkaller-12964-gccaff3d56acc #0
 | [  599.956099][T23028] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
 | [  600.092674][T23028] RIP: 0010:kcov_mmap+0xbe/0xe0
 | [  600.097559][T23028] Code: 48 81 c3 00 10 00 00 49 39 dc 77 c9 31 c0 5b 5d 41 5c 41 5d 41 5e c3 48 c7 c7 e9 4a 5b 8b c6 05 5a fc 28 0c 01 e8 bd c6 a0 07 <0f> 0b eb d2 4c 89 f7 e8 66 28 e8 07 b8 ea ff ff ff eb d1 66 66 2e
 | [  600.117319][T23028] RSP: 0018:ffffc9000c1cfc30 EFLAGS: 00010282
 | [  600.135794][T23028] RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000000
 | [  600.163986][T23028] RDX: ffff888051f40000 RSI: ffffffff815fce18 RDI: fffff52001839f78
 | [  600.188615][T23028] RBP: ffff88804fc6e210 R08: 0000000000000000 R09: 0000000000000000
 | [  600.196616][T23028] R10: ffffffff815f77ee R11: 0000000000000000 R12: 0000000000200000
 | [  600.214229][T23028] R13: ffff8880646c2500 R14: ffff8880646c2508 R15: ffff88804fc6e260
 | [  600.252864][T23028] FS:  00005555570e4400(0000) GS:ffff8880b9c00000(0000) knlGS:0000000000000000
 | [  600.283249][T23028] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
 | [  600.335749][T23028] CR2: 0000001b2c436000 CR3: 000000004ef16000 CR4: 00000000003506f0
 | [  600.390781][T23028] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
 | [  600.430312][T23028] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000600
 | [  600.441698][T23028] Call Trace:
 | [  600.447877][T23028]  <TASK>
 | [  600.451890][T23028]  mmap_region+0xba5/0x14a0
 | [  600.486043][T23028]  do_mmap+0x863/0xfa0
 | [  600.490544][T23028]  vm_mmap_pgoff+0x1b7/0x290
 | [  600.505607][T23028]  ksys_mmap_pgoff+0x40d/0x5a0
 | [  600.522165][T23028]  do_syscall_64+0x35/0x80
 | [  600.526655][T23028]  entry_SYSCALL_64_after_hwframe+0x44/0xae
 | [  600.532936][T23028] RIP: 0033:0x7f5be4889092
 | [  600.537407][T23028] Code: 00 00 00 00 00 0f 1f 00 41 f7 c1 ff 0f 00 00 75 27 55 48 89 fd 53 89 cb 48 85 ff 74 3b 41 89 da 48 89 ef b8 09 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 66 5b 5d c3 0f 1f 00 48 c7 c0 b8 ff ff ff 64
 | [  600.560042][T23028] RSP: 002b:00007fffde76b318 EFLAGS: 00000246 ORIG_RAX: 0000000000000009
 | [  600.569079][T23028] RAX: ffffffffffffffda RBX: 0000000000000001 RCX: 00007f5be4889092
 | [  600.577107][T23028] RDX: 0000000000000003 RSI: 0000000000200000 RDI: 0000000000000000
 | [  600.587064][T23028] RBP: 0000000000000000 R08: 00000000000000db R09: 0000000000000000
 | [  600.596119][T23028] R10: 0000000000000001 R11: 0000000000000246 R12: 00007f5be499c1dc
 | [  600.604977][T23028] R13: 0000000000000003 R14: 00007f5be499c1d0 R15: 0000000000000032
 | [  600.613026][T23028]  </TASK>
 | [  600.616066][T23028] Kernel panic - not syncing: panic_on_warn set ...

> Why do we emit a message at all?  What action can the user take upon
> seeing the message?

The message is mainly for the benefit of the test log, in this case the
fuzzer's log so that humans inspecting the log can figure out what was
going on. KCOV is a testing tool, so I think being a little more chatty
when KCOV unexpectedly is about to fail will save someone debugging
time.

We don't want the WARN, because it's not a kernel bug that syzbot should
report, and failure can happen if the fuzzer tries hard enough (as
above).

> Do we have a Fixes: for this?

The WARN was moved with b3d7fe86fbd0 ("kcov: properly handle subsequent
mmap calls"), so that'd be the only commit a backport would cleanly
apply to.

> From the info provided thus far I'm unable to determine whether a
> -stable backport is needed.  What are your thoughts on this?

The main problem is it only makes fuzzers try to report this as a bug
(which it is not). Backporting to kernels that have b3d7fe86fbd0 would
be reasonable, but wouldn't bother creating backports for older kernels.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ylkr2xrVbhQYwNLf%40elver.google.com.
