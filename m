Return-Path: <kasan-dev+bncBCF5XGNWYQBRBGEVX2OAMGQE4EBUCLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 1208E644BBF
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Dec 2022 19:31:54 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id e15-20020a5b0ccf000000b006ed1704b40csf16416020ybr.5
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Dec 2022 10:31:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670351513; cv=pass;
        d=google.com; s=arc-20160816;
        b=EasgoJwV9ZM33h2qGKA4Vud5HWIjPm12mSmgzy5A2sEm2LtmrEELXvHlz6yhk9btYg
         T0pp3Ugg1qKRp6s7bqypz57FxYdSCHEC7hTh2qGP8/CPaHUoEKza0YyCSfIAC4Kvyalm
         jb7mPoUDt5bRzU5EQIlcWkzH5UWXvIyD4G2Hwc2mAH1DzyOhjVYhVbfMQpldI/80heNj
         u+oMkQelRM1kjAkZgTqZUgshxQcURrU3uTM4czA030KNy+lA/bqxzeWfCeXyAA8q+0+2
         hpdJpcJVSKOwVI2/ttWBO3o3ekkeIihJGQOEoWkgtDwmoSrpYhuII5yqct3jJa0oH8bH
         It7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=eF9/b4Rby7dlZoBMi2VEppIvd7wgJ5Kh7cDIn0B6Jhw=;
        b=O18PKToViAUpZsCBxGx9LoPlnw/F29Y4a6xXAtf4BTwIPvo73y42dgtI8S/++iKoaF
         tRwGHGI/Vzuzalu5WWmrjJR09hkYA90MoVqiLvH6oxDuQu6USMSGmlzKY36X0Oe0Oep7
         nPSvEwPnktizWyZzaE4OSN348aRcbP+4Ls4ZikLVo2ZpVOXGJjMHmFrlJ7z6XrP8B9Df
         UIyZTLoWpx+NW4O05GBumhAx3mFHjyBfY1usYmbNYjUyFPT7kn++5BCoeDfZOjsQej4p
         6WbTFvJ5ofHZG3SPksQlj2m1xOLI9e8whZN2GZk6EhO5pgbO6IRpL4/mGtvRjktwg0Q0
         F3gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=TNO6BxsI;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eF9/b4Rby7dlZoBMi2VEppIvd7wgJ5Kh7cDIn0B6Jhw=;
        b=KVV8BWR8B5IoeYiUtMj6RzGDnjFexUq1pCEguWUmqUyqfToDmJFZFXinM36rYxFo3+
         iBIhg9D0u3flelOFwPxMdindMKn4DLP8Mk4cRhz4+nujdD6gnafBHUWyhiqTezt/ol/f
         VvuInSKFucsWIdACU+hBTcuJ+8WgUb6yWVegnmI0GlLQktTkWwJhVj7GcwbdoI2sRX9X
         Qmz9ezw/wIjCSwmPNM0ZprgreYGvaFHas0gPFnvnHe87N38j4s5WkAXygVuMishFlWKp
         wd79obXPqhVgGXtAF1q9uZ8YDiszJIpVYaMiuFOCOV7mh+y1dswF9slrfliu/aucyaBR
         3dRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eF9/b4Rby7dlZoBMi2VEppIvd7wgJ5Kh7cDIn0B6Jhw=;
        b=65ZRZB3sFLVBQMyMyOdXIS5rzLD05DOn5Ol4V5tcJci9yXnqp5KX2/5q0oAOPANL4j
         fb89uFQFH+pR3N5Wj1Rt+l4Y5WIXNTmnzLHHPa1QEPmwy3A2z3Qp0bjGw5uV6uPNrvp0
         AiJvyGrkIl0pbDTJ5Ea8lMvsnNG+2SeO6G101Jb87sPU8MkjkG6vH+RCAR1+UhE1WPaX
         7Uh2AB+XSMCSFQ05eirysuMKhglJUJOZTD24Jr5ivI+7k79EU4EIDaRwPiSPdNIIKgUj
         BUDv/sPponhIOawuusRkbaKDuNAR7JNWk3PiOo2q5BXd1/YpeGlFuT1nNQgyUBPt2ItZ
         H6Rg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnqbAXncm23+L4/fhyfcYs7oY5z21QO0/5XFVheTibkIkAaeTAL
	fpxE0jdPQlWzeRnRA4Qu3Z8=
X-Google-Smtp-Source: AA0mqf5gODNY9f7oKBSLKFfMWsyi9W0TUZCGMnVnDyfdzDAx+0HticXnVieZwM1wu82CEHIHjobscQ==
X-Received: by 2002:a81:4b05:0:b0:38d:e8f4:c8ba with SMTP id y5-20020a814b05000000b0038de8f4c8bamr16629751ywa.159.1670351512854;
        Tue, 06 Dec 2022 10:31:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ac01:0:b0:6e6:9336:f56d with SMTP id w1-20020a25ac01000000b006e69336f56dls62859ybi.3.-pod-prod-gmail;
 Tue, 06 Dec 2022 10:31:50 -0800 (PST)
X-Received: by 2002:a25:6042:0:b0:6f9:fd74:22f with SMTP id u63-20020a256042000000b006f9fd74022fmr28264079ybb.100.1670351509751;
        Tue, 06 Dec 2022 10:31:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670351509; cv=none;
        d=google.com; s=arc-20160816;
        b=rCo/Jo7uvo92BPEk9E10Si3zA6zcCrgR5VsiDDkARf5UQ/B9gNIX6zvMAIjNcsUm+7
         xnqOlKDH99iTcc+Ipz29y8QiIydT/xCvSd86jqrMDJSYiqgstmxdAFR7drhp/Vz3AzWh
         HsPRvHVBxq8FuEoHZKWzjeOhYkADSadYSNmfhcLvElfYO3niLC43zT4dlg7PcY9s56oD
         6XJZywATMhgI9sFBJgBvTnaTlpcbLltaiUOlSDkCe2ws1DXpUU7B/S4mBkvyRvzT7Ppg
         fNVnWY/4sK4pzdiyaQfI1zo1x38jFax2s3PbYV0LQ8GDRvU83RMgzmT2KIh+QoWlsYfy
         xNzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KqUAYb/fXjf+DnnONFt9R7wczdlGsDniuWCIhYP8EcQ=;
        b=xx/HEVpWUSOi2AW1aRwGKTxnE4cSDEy/LhTlO71Kuk7MzG5uIoIQRZDL8T9NNlh+lL
         na6vf9KLN9R9KVAvu5mah9w+LVILd5gTBjRi5omFLLzw4bHQCxE60MZEUo2nUFazlwVm
         O0p/+IQm33yhk3dMC5ls9UEGbxitVO3Vt/EMeOlG3z9mA+5pNMDZa6Mo62khDt0Vo7gY
         mS5R7/JLnIZSOQR8451ShDPIhUlVV9fqJwymOGNcFBmas6YB2QF/XLm1tq+xhBp/BQmL
         qfHTTT8B2DkQgivB01JjQwKTPAmP/U5p3dKrUHlq4zb8uZzR4z0BnwpQ22TBn23EssfU
         dp9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=TNO6BxsI;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-qt1-x831.google.com (mail-qt1-x831.google.com. [2607:f8b0:4864:20::831])
        by gmr-mx.google.com with ESMTPS id k21-20020a25c615000000b006ddea715dd2si1245538ybf.0.2022.12.06.10.31.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Dec 2022 10:31:49 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::831 as permitted sender) client-ip=2607:f8b0:4864:20::831;
Received: by mail-qt1-x831.google.com with SMTP id c15so14410083qtw.8
        for <kasan-dev@googlegroups.com>; Tue, 06 Dec 2022 10:31:49 -0800 (PST)
X-Received: by 2002:a05:622a:a0a:b0:3a5:1ea9:711e with SMTP id bv10-20020a05622a0a0a00b003a51ea9711emr79192490qtb.280.1670351509038;
        Tue, 06 Dec 2022 10:31:49 -0800 (PST)
Received: from mail-yw1-f171.google.com (mail-yw1-f171.google.com. [209.85.128.171])
        by smtp.gmail.com with ESMTPSA id l27-20020ac84cdb000000b00399fe4aac3esm11676378qtv.50.2022.12.06.10.31.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Dec 2022 10:31:47 -0800 (PST)
Received: by mail-yw1-f171.google.com with SMTP id 00721157ae682-3c21d6e2f3aso161078697b3.10
        for <kasan-dev@googlegroups.com>; Tue, 06 Dec 2022 10:31:47 -0800 (PST)
X-Received: by 2002:a81:8644:0:b0:3c7:3c2b:76b5 with SMTP id
 w65-20020a818644000000b003c73c2b76b5mr39379193ywf.22.1670351506938; Tue, 06
 Dec 2022 10:31:46 -0800 (PST)
MIME-Version: 1.0
References: <000000000000fa798505ee880a25@google.com> <ac0d8823-e7b3-4524-8864-89b4c85315b5n@googlegroups.com>
 <CACT4Y+bz-z9s+sDh916rfw9ezW0XROkAKfMDvdVi-wDuf849MQ@mail.gmail.com>
In-Reply-To: <CACT4Y+bz-z9s+sDh916rfw9ezW0XROkAKfMDvdVi-wDuf849MQ@mail.gmail.com>
From: Kees Cook <keescook@chromium.org>
Date: Tue, 6 Dec 2022 10:31:10 -0800
X-Gmail-Original-Message-ID: <CAGXu5jLCdfVLz9PLVs4XkyOY3=V=W8x7WF=E+yRUnsE=425vAw@mail.gmail.com>
Message-ID: <CAGXu5jLCdfVLz9PLVs4XkyOY3=V=W8x7WF=E+yRUnsE=425vAw@mail.gmail.com>
Subject: Re: [syzbot] KASAN: slab-out-of-bounds Write in __build_skb_around
To: Dmitry Vyukov <dvyukov@google.com>
Cc: pepsipu <soopthegoop@gmail.com>, 
	syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Andrii Nakryiko <andrii@kernel.org>, ast@kernel.org, 
	bpf <bpf@vger.kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, 
	David Miller <davem@davemloft.net>, Eric Dumazet <edumazet@google.com>, Hao Luo <haoluo@google.com>, 
	Jesper Dangaard Brouer <hawk@kernel.org>, John Fastabend <john.fastabend@gmail.com>, jolsa@kernel.org, 
	KP Singh <kpsingh@kernel.org>, Jakub Kicinski <kuba@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, martin.lau@linux.dev, 
	netdev <netdev@vger.kernel.org>, Paolo Abeni <pabeni@redhat.com>, 
	Stanislav Fomichev <sdf@google.com>, song@kernel.org, Yonghong Song <yhs@fb.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=TNO6BxsI;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::831
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Dec 5, 2022 at 12:04 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Sun, 4 Dec 2022 at 19:16, pepsipu <soopthegoop@gmail.com> wrote:
> >
> > I believe this is a KASAN bug.
> >
> > I made an easier to read version that still triggers KASAN:
> >
> > #define _GNU_SOURCE
> >
> > #include <stdio.h>
> > #include <stdlib.h>
> > #include <string.h>
> > #include <sys/syscall.h>
> > #include <sys/types.h>
> > #include <linux/bpf.h>
> > #include <unistd.h>
> >
> > #include "bpf.h"
> >
> > int main(void)
> > {
> >     __u64 insns[] = {
> >         (BPF_CALL | BPF_JMP) | ((__u64)0x61 << 32),
> >         (BPF_AND | BPF_ALU),
> >         (BPF_EXIT | BPF_JMP),
> >     };
> >     bpf_load_attr_t load_attr = {
> >         .prog_type = BPF_PROG_TYPE_CGROUP_SKB,
> >         .insn_cnt = sizeof(insns) / sizeof(__u64),
> >         .insns = (__u64)insns,
> >         .license = (__u64) "GPL",
> >     };
> >     long prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &load_attr, sizeof(bpf_load_attr_t));
> >     if (prog_fd == -1)
> >     {
> >         printf("could not load bpf prog");
> >         exit(-1);
> >     }
> >     bpf_trun_attr_t trun_attr = {
> >         .prog_fd = prog_fd,
> >         .data_size_in = 0x81,
> >         .data_size_out = -1,
> >         .data_in = (__u64) "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
> >     };
> >
> >     syscall(__NR_bpf, BPF_PROG_TEST_RUN, &trun_attr, sizeof(bpf_trun_attr_t));
> >     return 0;
> > }
> >
> > It looks like KASAN believes the tail access of SKB's backing buffer, the SKB shared info struct, allocated by bpf_test_init is out-of-bounds.
> > This is likely because when the SKB is setup, in build_skb, the tail is calculated as "data + ksize(data) - sizeof(skb_shared_info)". ksize returns the size of the slab, not the allocation, so the tail is much further past the allocation.
> > However, KASAN is usually supposed to correct for ksize calls by unpoisioning the entire slab it's called on... I'm not sure why this is happening.
>
> Hi,
>
> [+orignal CC list, please keep it in replies, almost none of relevant
> receivers read syzkaller-bugs@ mailing list]
>
> Also +Kees and kasan-dev for ksize.
>
> After the following patch the behavior has changed and KASAN does not
> unpoison the fail of the object:
>
> mm: Make ksize() a reporting-only function
> https://lore.kernel.org/all/20221118035656.gonna.698-kees@kernel.org/
>
> Kees, is this bpf case is a remaining ksize() use that needs to be fixed?
>

Hi, yes, this seems like a missed ksize() usage. I will take a look at
it -- nothing should be using ksize() to resize the allocation any
more: it should either fully allocate the bucket at the start, or use
krealloc().

-Kees

> > On Monday, November 28, 2022 at 5:42:31 AM UTC-8 syzbot wrote:
> >>
> >> Hello,
> >>
> >> syzbot found the following issue on:
> >>
> >> HEAD commit: c35bd4e42885 Add linux-next specific files for 20221124
> >> git tree: linux-next
> >> console+strace: https://syzkaller.appspot.com/x/log.txt?x=15e5d7e5880000
> >> kernel config: https://syzkaller.appspot.com/x/.config?x=11e19c740a0b2926
> >> dashboard link: https://syzkaller.appspot.com/bug?extid=fda18eaa8c12534ccb3b
> >> compiler: gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2
> >> syz repro: https://syzkaller.appspot.com/x/repro.syz?x=1096f205880000
> >> C reproducer: https://syzkaller.appspot.com/x/repro.c?x=10b2d68d880000
> >>
> >> Downloadable assets:
> >> disk image: https://storage.googleapis.com/syzbot-assets/968fee464d14/disk-c35bd4e4.raw.xz
> >> vmlinux: https://storage.googleapis.com/syzbot-assets/4f46fe801b5b/vmlinux-c35bd4e4.xz
> >> kernel image: https://storage.googleapis.com/syzbot-assets/c2cdf8fb264e/bzImage-c35bd4e4.xz
> >>
> >> IMPORTANT: if you fix the issue, please add the following tag to the commit:
> >> Reported-by: syzbot+fda18e...@syzkaller.appspotmail.com
> >>
> >> ==================================================================
> >> BUG: KASAN: slab-out-of-bounds in __build_skb_around+0x235/0x340 net/core/skbuff.c:294
> >> Write of size 32 at addr ffff88802aa172c0 by task syz-executor413/5295
> >>
> >> CPU: 0 PID: 5295 Comm: syz-executor413 Not tainted 6.1.0-rc6-next-20221124-syzkaller #0
> >> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 10/26/2022
> >> Call Trace:
> >> <TASK>
> >> __dump_stack lib/dump_stack.c:88 [inline]
> >> dump_stack_lvl+0xd1/0x138 lib/dump_stack.c:106
> >> print_address_description mm/kasan/report.c:253 [inline]
> >> print_report+0x15e/0x45d mm/kasan/report.c:364
> >> kasan_report+0xbf/0x1f0 mm/kasan/report.c:464
> >> check_region_inline mm/kasan/generic.c:183 [inline]
> >> kasan_check_range+0x141/0x190 mm/kasan/generic.c:189
> >> memset+0x24/0x50 mm/kasan/shadow.c:44
> >> __build_skb_around+0x235/0x340 net/core/skbuff.c:294
> >> __build_skb+0x4f/0x60 net/core/skbuff.c:328
> >> build_skb+0x22/0x280 net/core/skbuff.c:340
> >> bpf_prog_test_run_skb+0x343/0x1e10 net/bpf/test_run.c:1131
> >> bpf_prog_test_run kernel/bpf/syscall.c:3644 [inline]
> >> __sys_bpf+0x1599/0x4ff0 kernel/bpf/syscall.c:4997
> >> __do_sys_bpf kernel/bpf/syscall.c:5083 [inline]
> >> __se_sys_bpf kernel/bpf/syscall.c:5081 [inline]
> >> __x64_sys_bpf+0x79/0xc0 kernel/bpf/syscall.c:5081
> >> do_syscall_x64 arch/x86/entry/common.c:50 [inline]
> >> do_syscall_64+0x39/0xb0 arch/x86/entry/common.c:80
> >> entry_SYSCALL_64_after_hwframe+0x63/0xcd
> >> RIP: 0033:0x7f30de9aad19
> >> Code: 28 c3 e8 2a 14 00 00 66 2e 0f 1f 84 00 00 00 00 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 c0 ff ff ff f7 d8 64 89 01 48
> >> RSP: 002b:00007ffeaee34318 EFLAGS: 00000246 ORIG_RAX: 0000000000000141
> >> RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007f30de9aad19
> >> RDX: 0000000000000028 RSI: 0000000020000180 RDI: 000000000000000a
> >> RBP: 00007f30de96eec0 R08: 0000000000000000 R09: 0000000000000000
> >> R10: 0000000000000000 R11: 0000000000000246 R12: 00007f30de96ef50
> >> R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
> >> </TASK>
> >>
> >> Allocated by task 5295:
> >> kasan_save_stack+0x22/0x40 mm/kasan/common.c:45
> >> kasan_set_track+0x25/0x30 mm/kasan/common.c:52
> >> ____kasan_kmalloc mm/kasan/common.c:376 [inline]
> >> ____kasan_kmalloc mm/kasan/common.c:335 [inline]
> >> __kasan_kmalloc+0xa5/0xb0 mm/kasan/common.c:385
> >> kasan_kmalloc include/linux/kasan.h:212 [inline]
> >> __do_kmalloc_node mm/slab_common.c:955 [inline]
> >> __kmalloc+0x5a/0xd0 mm/slab_common.c:968
> >> kmalloc include/linux/slab.h:575 [inline]
> >> kzalloc include/linux/slab.h:711 [inline]
> >> bpf_test_init.isra.0+0xa5/0x150 net/bpf/test_run.c:778
> >> bpf_prog_test_run_skb+0x22e/0x1e10 net/bpf/test_run.c:1097
> >> bpf_prog_test_run kernel/bpf/syscall.c:3644 [inline]
> >> __sys_bpf+0x1599/0x4ff0 kernel/bpf/syscall.c:4997
> >> __do_sys_bpf kernel/bpf/syscall.c:5083 [inline]
> >> __se_sys_bpf kernel/bpf/syscall.c:5081 [inline]
> >> __x64_sys_bpf+0x79/0xc0 kernel/bpf/syscall.c:5081
> >> do_syscall_x64 arch/x86/entry/common.c:50 [inline]
> >> do_syscall_64+0x39/0xb0 arch/x86/entry/common.c:80
> >> entry_SYSCALL_64_after_hwframe+0x63/0xcd

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGXu5jLCdfVLz9PLVs4XkyOY3%3DV%3DW8x7WF%3DE%2ByRUnsE%3D425vAw%40mail.gmail.com.
