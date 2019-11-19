Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBKMP2HXAKGQERS4MK3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 42D3A102D01
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 20:51:07 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id a5sf13722365pln.13
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 11:51:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574193066; cv=pass;
        d=google.com; s=arc-20160816;
        b=laj/opYYSYzQZjl7OpQjL25Ff2fLv7mzupgB0n7xSVGLwgAr5OSJzq4OMCRSOdAb0g
         dQusBv07+mUec5AtmZ5DsqkRIiqYgdLVKt18fl518shN2lhJKCq+uXoVICJCyyQmlTW+
         XMwlWCMRkB/Dmj8gOJOy7KODUXDFEC7inUwLy5g07DEc366Hh3kZEPzrPWTG2HNVuQ6A
         dMzN3VixrHmuwSCoHglbtJq/sNe/l6LJvkqBK7j81RSRV4sj+v4dd96pNFct4J7i/lWj
         mhefd1BZ1+86M/gGOhc8f3InrNG8SrF9EnkoyHrgdVtJGr8+WOohgU7ER4zIzRUoNMN1
         LpYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=YGY1ClMD8bhi1glIilAVkD1/VXwlu0EICF35sihS1T0=;
        b=uPHcuQyk4D6GUMkws1oig7iw1zkC4Uf+Q49EnkxiLJAjRIn66kFPDUxc5i31xXQ/KD
         kCg1FJGPCZDKjq6ghOO5k0+wV2fXfS7T6ynDT+Af2ebfE1asqbyQcwa0KXGs4ftcH7Tr
         ySOCffKxI2PnnxfdX6EYkO951KGOnPkADi34Xkjm3aZH/H1ZsVfBhB/wtXR3/zTio11V
         KyZfw5ehC/n1SHxVvaXUQ243mxlb6Ti3L2+Ql30rpOxN01VtojcGTw0kIEgVA59q3JG6
         a9jxHmjD5xo2w6GuQc/QtwRd7PXoVFUbInVQDClT3HYhpaFeuzhpNNKP1vMRB1oIjlEY
         SA/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=T1mhHDOS;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YGY1ClMD8bhi1glIilAVkD1/VXwlu0EICF35sihS1T0=;
        b=lNPuayFUKkyk8Unaxf0VqqUwMa6VLWlJo6Zn+KO7JnpUj42rm/LC3XXwDeVr0PVe9a
         UCyzkbfzluoGTrGgLOFVjXQRnFIDi1JabrXOhIuCEiCMVp0l1n1mbFyjQjAOcNtOIwaa
         7q/gLOAYOqfo850mZ5ZpTFvQ7A8wQaZ/73ATSPARHsLB+Otl4KmxhEkSckOuLsHOz74e
         pSrgjnReFPn9DP0AhW5syco4ubioFejF9ScTOYzWdYEj74V610vZt1O4tex1oNv0MbFJ
         G5CxwjGeud4WvMazInX/xlRt9IW4hBfTULwBrw9ViIW9pBL+nmpEc1I0bcVGQOpKFV9L
         FYAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YGY1ClMD8bhi1glIilAVkD1/VXwlu0EICF35sihS1T0=;
        b=WOuZO0LSEkg9MiKj2+WDdqHvIFj6FZPqUnPPvatk+dHplNyDcuTogdjiF4UgKQeb19
         QJC6ZpGf7ObMdKLNGt+lPkHZzUybrheLSkPcgoNJnOamqKgsnbIN5QBYjEhmkRbNyiR6
         D7e7tjWgFI+C66TatsrF+T1jdsWY8vofr1zFqK2hImO9CDINoXTOVLNvIeeetvP5MKRI
         lQ6TOKMQDI2cUVXOoYmdBadEmxsIq5OI5dgLx4t4txjQEEM4+KFwq0KM4RW29xRPgPFr
         ZReg3EMvRZBoZ1ZkXe2vpIgem9Ikm66WvImVk/NKacSuOlojb6KwG/Tw7KcNw8EfCW3z
         Dcow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXop7mXm4oLQasJ+mGnyv0UASKw7h88Yn4j8kOKoIw9n990x42l
	dbcgxxWxu6Kb+Wec1g+CyiY=
X-Google-Smtp-Source: APXvYqyHSqe2RG3+7W+1oFWCMcLSxYeUTrsozcesg/oZEyoZv67st5z65wCc0m2lSCdTw73GCpgC4Q==
X-Received: by 2002:aa7:971d:: with SMTP id a29mr7920197pfg.205.1574193065843;
        Tue, 19 Nov 2019 11:51:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:2ec5:: with SMTP id u188ls5343673pfu.0.gmail; Tue, 19
 Nov 2019 11:51:05 -0800 (PST)
X-Received: by 2002:a63:4821:: with SMTP id v33mr2252908pga.282.1574193065386;
        Tue, 19 Nov 2019 11:51:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574193065; cv=none;
        d=google.com; s=arc-20160816;
        b=FmXS2GmzVKnAGhFCJXlV0aCD7ERqni/QTzSab8CKW3hQ88zPypAYK9Dhwgm0Wy/+Cq
         n+8S3RsiFUG5MHjpLsJdO8aIiGsch8aPS1gHM+QYSyktfS6IFEY2Nmt7FVcFWlQkA4zw
         Jkhdrh8v2jJtY05r5pp5IyNtKMFQHlnO8VUzZrU1T6rQ9OwYkFtZ5XbZiFvbws6EY95Y
         5NnQfBWkj2V3R2bizpSzxeHHzO8wk+X5yNFctwLH0c9mt3RbVo0ieKzskDPRC7pI++B9
         fFeUPGbUCrmZSLA8WtCxiFYUiCx5rmL3U92bh3qIz2ZCAal9h6IjMvNNNLGS1IDNZly+
         xLTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=SJkWiQS++k8drSI02mEHrqK7VAxEXqYSD3skFTgLnIk=;
        b=N54iV+SBIuSkQk7f0V31rBJ4btE3BDlul66FcBdprJ6frRIp3j24LraNeRCjgNCEpY
         3lM6waZG/MlyF5/6w7MuTHPUtXGggpJNB3jrux1F7crP/3jI7WXM6q/IeHFeibAp9RXw
         u0LAjMVp8cinJWA7U4myVuLdN/LlVp2Z2GVBVfTVvIeGoiXQokVGXHEmGbx1Em47Bk/s
         Q0pNW5Ai1L3XqsLG3Q18KEX1ibFhGI3NorP4YnFbFf2eIwUHHmftRHVQtxf9VtIEtEbk
         c4pSSv8ic8S5KKyiCiaDCI7LRULrYAq+yU1ZooUN5g5UocLuVmp09nestb7kDwmRY5O3
         Yfog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=T1mhHDOS;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id g15si1082629plq.0.2019.11.19.11.51.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 11:51:05 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id v16so8675447qvq.6
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 11:51:05 -0800 (PST)
X-Received: by 2002:a0c:e847:: with SMTP id l7mr279965qvo.14.1574193064216;
        Tue, 19 Nov 2019 11:51:04 -0800 (PST)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id y24sm10542040qki.104.2019.11.19.11.51.00
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Nov 2019 11:51:03 -0800 (PST)
Message-ID: <1574193059.9585.8.camel@lca.pw>
Subject: Re: [PATCH v4 00/10] Add Kernel Concurrency Sanitizer (KCSAN)
From: Qian Cai <cai@lca.pw>
To: Marco Elver <elver@google.com>
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
 parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
 ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com,
 bp@alien8.de,  dja@axtens.net, dlustig@nvidia.com,
 dave.hansen@linux.intel.com,  dhowells@redhat.com, dvyukov@google.com,
 hpa@zytor.com, mingo@redhat.com,  j.alglave@ucl.ac.uk,
 joel@joelfernandes.org, corbet@lwn.net, jpoimboe@redhat.com, 
 luc.maranget@inria.fr, mark.rutland@arm.com, npiggin@gmail.com,
 paulmck@kernel.org,  peterz@infradead.org, tglx@linutronix.de,
 will@kernel.org, edumazet@google.com,  kasan-dev@googlegroups.com,
 linux-arch@vger.kernel.org,  linux-doc@vger.kernel.org,
 linux-efi@vger.kernel.org,  linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,  x86@kernel.org
Date: Tue, 19 Nov 2019 14:50:59 -0500
In-Reply-To: <20191114180303.66955-1-elver@google.com>
References: <20191114180303.66955-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=T1mhHDOS;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f44 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Thu, 2019-11-14 at 19:02 +0100, 'Marco Elver' via kasan-dev wrote:
> This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> KCSAN is a sampling watchpoint-based *data race detector*. More details
> are included in **Documentation/dev-tools/kcsan.rst**. This patch-series
> only enables KCSAN for x86, but we expect adding support for other
> architectures is relatively straightforward (we are aware of
> experimental ARM64 and POWER support).

Just booting x86 systems because kcsan_setup_watchpoint() disabled hard irq=
s?

[=C2=A0=C2=A0=C2=A0=C2=A08.926145][=C2=A0=C2=A0=C2=A0=C2=A0T0] ------------=
[ cut here ]------------
[=C2=A0=C2=A0=C2=A0=C2=A08.927850][=C2=A0=C2=A0=C2=A0=C2=A0T0] DEBUG_LOCKS_=
WARN_ON(!current->hardirqs_enabled)
[=C2=A0=C2=A0=C2=A0=C2=A080] WARNING: CPU: 0 PID: 0 at kernel/locking/lockd=
ep.c:4406
check_flags.part.26+0x102/0x240
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] Modules link=
ed in:
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] CPU: 0 PID: =
0 Comm: swapper/0 Not tainted 5.4.0-rc8-next-
20191119+ #2
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] Hardware nam=
e: HP ProLiant XL420 Gen9/ProLiant XL420
Gen9, BIOS U19 12/27/2015
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] RIP: 0010:ch=
eck_flags.part.26+0x102/0x240
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] Code: 7b a2 =
e8 51 6d 15 00 44 8b 05 fa df 45 01 45 85 c0
0f 85 27 76 00 00 48 c7 c6 02 d6 3b a2 48 c7 c7 79 36 3b a2 e8 2f 9f f5 ff =
<0f>
e9 0d 76 00 00 65 48 8b 3c 25 40 3f 01 00 e8 89 f0 ff ff e8
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] RSP: 0000:ff=
ffffffa2603860 EFLAGS: 00010086
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] RAX: 0000000=
000000000 RBX: ffffffffa2617b40 RCX:
0000000000000000
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] RDX: 0000000=
000000000 RSI: 0000000000000001 RDI:
0000000000000000
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] RBP: fffffff=
fa2603868 R08: 0000000000000000 R09:
0000ffffa27bcad4
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] R10: 0000fff=
fffffffff R11: 0000ffffa27bcad7 R12:
0000000000000168
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] R13: 0000000=
000092cc0 R14: 0000000000000246 R15:
ffffffffa1664c89
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] FS:=C2=A0=C2=
=A00000000000000000(0000) GS:ffff8987f3000000(0000)
knlGS:0000000000000000
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] CS:=C2=A0=C2=
=A00010 DS: 0000 ES: 0000 CR0: 0000000080050033
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] CR2: ffff898=
bfc9ff000 CR3: 000000033dc0e001 CR4:
00000000001606f0
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] Call Trace:
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0l=
ock_is_held_type+0x66/0x13072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0?
rcu_is_watching+0x79/0xa0
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0?=
 create_object+0x69/0x690
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0r=
cu_read_lock_sched_held+0x7f/0xa0
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0k=
mem_cache_alloc+0x3b2/0x420
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0?=
 create_object+0x69/0x690
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0c=
reate_object+0x69/0x690
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0?=
 find_next_bit+0x7b/0xa0
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0k=
memleak_alloc_percpu+0xde/0x170
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0p=
cpu_alloc+0x683/0xc90
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0_=
_alloc_percpu+0x2d/0x40
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0a=
lloc_vfsmnt+0xd1/0x380
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0v=
fs_create_mount+0x7f/0x2e0
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0?=
 proc_get_tree+0x4d/0x60
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0f=
c_mount+0x6d/0x80
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0p=
id_ns_prepare_proc+0x133/0x190
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0a=
lloc_pid+0x5c3/0x600
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0c=
opy_process+0x1ca3/0x3480
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0?=
 __lock_acquire+0x739/0x25d0
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0_=
do_fork+0xaa/0x9c0
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0?=
 rcu_blocking_is_gp+0x83/0xb0
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0?=
 synchronize_rcu_expedited+0x80/0x6c0
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0?=
 rcu_blocking_is_gp+0x83/0xb0
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0?=
 rest_init+0x381/0x381
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0k=
ernel_thread+0xb0/0xe0
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0?=
 rest_init+0x381/0x381
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0r=
est_init+0x31/0x381
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0st_init+0x17/0x29
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0s=
tart_kernel+0x6ac/0x6d0
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0x=
86_64_start_reservations+0x24/0x26
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0x=
86_64_start_kernel+0xef/0xf6
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0]=C2=A0=C2=A0s=
econdary_startup_64+0xb6/0xc0
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] irq event st=
amp: 75594
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] hardirqs las=
t=C2=A0=C2=A0enabled at (75593): [<ffffffffa1203d52>]
trace_hardirqs_on_thunk+0x1a/0x1c
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] hardirqs las=
t disabled at (75594): [<ffffffffa14b4f96>]
kcsan_setup_watchpoint+0x96/0x200
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] softirqs las=
t=C2=A0=C2=A0enabled at (75592): [<ffffffffa200034c>]
__do_softirq+0x34c/0x57c
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] softirqs las=
t disabled at (75585): [<ffffffffa12c6fb2>]
irq_exit+0xa2/0xc0
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] ---[ end tra=
ce f4a667495da45c20 ]---
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] possible rea=
son: unannotated irqs-on.
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] irq event st=
amp: 75594
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] hardirqs las=
t=C2=A0=C2=A0enabled at (75593): [<ffffffffa1203d52>]
trace_hardirqs_on_thunk+0x1a/0x1c
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] hardirqs las=
t disabled at (75594): [<ffffffffa14b4f96>]
kcsan_setup_watchpoint+0x96/0x200
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] softirqs las=
t=C2=A0=C2=A0enabled at (75592): [<ffffffffa200034c>]
__do_softirq+0x34c/0x57c
[=C2=A0=C2=A0=C2=A0=C2=A08.933072][=C2=A0=C2=A0=C2=A0=C2=A0T0] softirqs las=
t disabled at (75585): [<ffffffffa12c6fb2>]
irq_exit+0xa2/0xc0


>=20
> To gather early feedback, we announced KCSAN back in September, and have
> integrated the feedback where possible:
> http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu=
1eA@mail.gmail.com
>=20
> The current list of known upstream fixes for data races found by KCSAN
> can be found here:
> https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-f=
ound-by-kcsan
>=20
> We want to point out and acknowledge the work surrounding the LKMM,
> including several articles that motivate why data races are dangerous
> [1, 2], justifying a data race detector such as KCSAN.
>=20
> [1] https://lwn.net/Articles/793253/
> [2] https://lwn.net/Articles/799218/
>=20
> Race conditions vs. data races
> ------------------------------
>=20
> Race conditions are logic bugs, where unexpected interleaving of racing
> concurrent operations result in an erroneous state.
>=20
> Data races on the other hand are defined at the *memory model/language
> level*.  Many data races are also harmful race conditions, which a tool
> like KCSAN reports!  However, not all data races are race conditions and
> vice-versa.  KCSAN's intent is to report data races according to the
> LKMM. A data race detector can only work at the memory model/language
> level.
>=20
> Deeper analysis, to find high-level race conditions only, requires
> conveying the intended kernel logic to a tool. This requires (1) the
> developer writing a specification or model of their code, and then (2)
> the tool verifying that the implementation matches. This has been done
> for small bits of code using model checkers and other formal methods,
> but does not scale to the level of what can be covered with a dynamic
> analysis based data race detector such as KCSAN.
>=20
> For reasons outlined in [1, 2], data races can be much more subtle, but
> can cause no less harm than high-level race conditions.
>=20
> Changelog
> ---------
> v4:
> * Major changes:
>  - Optimizations resulting in performance improvement of 33% (on
>    microbenchmark).
>  - Deal with nested interrupts for atomic_next.
>  - Simplify report.c (removing double-locking as well), in preparation
>    for KCSAN_REPORT_VALUE_CHANGE_ONLY.
>  - Add patch to introduce "data_race(expr)" macro.
>  - Introduce KCSAN_REPORT_VALUE_CHANGE_ONLY option for further filtering =
of data
>    races: if a conflicting write was observed via a watchpoint, only repo=
rt the
>    data race if a value change was observed as well. The option will be e=
nabled
>    by default on syzbot. (rcu-functions will be excluded from this filter=
 at
>    request of Paul McKenney.) Context:
>    http://lkml.kernel.org/r/CANpmjNOepvb6+zJmDePxj21n2rctM4Sp4rJ66x_J-L1U=
mNK54A@mail.gmail.com
>=20
> v3: http://lkml.kernel.org/r/20191104142745.14722-1-elver@google.com
> * Major changes:
>  - Add microbenchmark.
>  - Add instruction watchpoint skip randomization.
>  - Refactor API and core runtime fast-path and slow-path. Compared to
>    the previous version, with a default config and benchmarked using the
>    added microbenchmark, this version is 3.8x faster.
>  - Make __tsan_unaligned __alias of generic accesses.
>  - Rename kcsan_{begin,end}_atomic ->
>    kcsan_{nestable,flat}_atomic_{begin,end}
>  - For filter list in debugfs.c use kmalloc+krealloc instead of
>    kvmalloc.
>  - Split Documentation into separate patch.
>=20
> v2: http://lkml.kernel.org/r/20191017141305.146193-1-elver@google.com
> * Major changes:
>  - Replace kcsan_check_access(.., {true, false}) with
>    kcsan_check_{read,write}.
>  - Change atomic-instrumented.h to use __atomic_check_{read,write}.
>  - Use common struct kcsan_ctx in task_struct and for per-CPU interrupt
>    contexts.
>=20
> v1: http://lkml.kernel.org/r/20191016083959.186860-1-elver@google.com
>=20
> Marco Elver (10):
>   kcsan: Add Kernel Concurrency Sanitizer infrastructure
>   include/linux/compiler.h: Introduce data_race(expr) macro
>   kcsan: Add Documentation entry in dev-tools
>   objtool, kcsan: Add KCSAN runtime functions to whitelist
>   build, kcsan: Add KCSAN build exceptions
>   seqlock, kcsan: Add annotations for KCSAN
>   seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
>   asm-generic, kcsan: Add KCSAN instrumentation for bitops
>   locking/atomics, kcsan: Add KCSAN instrumentation
>   x86, kcsan: Enable KCSAN for x86
>=20
>  Documentation/dev-tools/index.rst         |   1 +
>  Documentation/dev-tools/kcsan.rst         | 256 +++++++++
>  MAINTAINERS                               |  11 +
>  Makefile                                  |   3 +-
>  arch/x86/Kconfig                          |   1 +
>  arch/x86/boot/Makefile                    |   2 +
>  arch/x86/boot/compressed/Makefile         |   2 +
>  arch/x86/entry/vdso/Makefile              |   3 +
>  arch/x86/include/asm/bitops.h             |   6 +-
>  arch/x86/kernel/Makefile                  |   4 +
>  arch/x86/kernel/cpu/Makefile              |   3 +
>  arch/x86/lib/Makefile                     |   4 +
>  arch/x86/mm/Makefile                      |   4 +
>  arch/x86/purgatory/Makefile               |   2 +
>  arch/x86/realmode/Makefile                |   3 +
>  arch/x86/realmode/rm/Makefile             |   3 +
>  drivers/firmware/efi/libstub/Makefile     |   2 +
>  include/asm-generic/atomic-instrumented.h | 393 +++++++-------
>  include/asm-generic/bitops-instrumented.h |  18 +
>  include/linux/compiler-clang.h            |   9 +
>  include/linux/compiler-gcc.h              |   7 +
>  include/linux/compiler.h                  |  57 +-
>  include/linux/kcsan-checks.h              |  97 ++++
>  include/linux/kcsan.h                     | 115 ++++
>  include/linux/sched.h                     |   4 +
>  include/linux/seqlock.h                   |  51 +-
>  init/init_task.c                          |   8 +
>  init/main.c                               |   2 +
>  kernel/Makefile                           |   6 +
>  kernel/kcsan/Makefile                     |  11 +
>  kernel/kcsan/atomic.h                     |  27 +
>  kernel/kcsan/core.c                       | 626 ++++++++++++++++++++++
>  kernel/kcsan/debugfs.c                    | 275 ++++++++++
>  kernel/kcsan/encoding.h                   |  94 ++++
>  kernel/kcsan/kcsan.h                      | 108 ++++
>  kernel/kcsan/report.c                     | 320 +++++++++++
>  kernel/kcsan/test.c                       | 121 +++++
>  kernel/sched/Makefile                     |   6 +
>  lib/Kconfig.debug                         |   2 +
>  lib/Kconfig.kcsan                         | 118 ++++
>  lib/Makefile                              |   3 +
>  mm/Makefile                               |   8 +
>  scripts/Makefile.kcsan                    |   6 +
>  scripts/Makefile.lib                      |  10 +
>  scripts/atomic/gen-atomic-instrumented.sh |  17 +-
>  tools/objtool/check.c                     |  18 +
>  46 files changed, 2641 insertions(+), 206 deletions(-)
>  create mode 100644 Documentation/dev-tools/kcsan.rst
>  create mode 100644 include/linux/kcsan-checks.h
>  create mode 100644 include/linux/kcsan.h
>  create mode 100644 kernel/kcsan/Makefile
>  create mode 100644 kernel/kcsan/atomic.h
>  create mode 100644 kernel/kcsan/core.c
>  create mode 100644 kernel/kcsan/debugfs.c
>  create mode 100644 kernel/kcsan/encoding.h
>  create mode 100644 kernel/kcsan/kcsan.h
>  create mode 100644 kernel/kcsan/report.c
>  create mode 100644 kernel/kcsan/test.c
>  create mode 100644 lib/Kconfig.kcsan
>  create mode 100644 scripts/Makefile.kcsan
>=20
> --=20
> 2.24.0.rc1.363.gb1bccd3e3d-goog
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1574193059.9585.8.camel%40lca.pw.
